# controller.py

import asyncio
import fcntl
import ipaddress
import os
import re
import secrets
import shlex
import time

from contextlib import contextmanager
from datetime import datetime, timezone

import yaml

from intent_config import (
    AUDIT_PATH,
    BASE_DIR,
    find_intent,
    fingerprint,
    is_authorized,
    load_config,
)


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def controller_lock():
    path = BASE_DIR / ".controller.lock"

    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def audit(event, payload):
    record = {
        "timestamp": now(),
        "event": event,
        "payload": payload,
    }

    lock_path = BASE_DIR / ".audit.lock"

    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)

        try:
            with AUDIT_PATH.open("a", encoding="utf-8") as handle:
                yaml.safe_dump(
                    record,
                    handle,
                    explicit_start=True,
                    sort_keys=False,
                )
                handle.flush()
                os.fsync(handle.fileno())

        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def privileged(argv):
    if os.geteuid() == 0:
        return argv

    return ["sudo", "-n", *argv]


def ask_approval(plan):
    print("\nTool use")
    print(f"\nPurpose:\n{plan['purpose']}")

    if "command" in plan:
        print(f"\nCommand:\n{plan['command']}")
    else:
        print(f"\nOperation:\n{plan['operation']}")

    for attempt in range(1, 4):
        answer = input(
            "\nDo you want to allow this? (yes/no)\n-> "
        ).strip().lower()

        if answer == "yes":
            return True

        if answer == "no":
            return False

        print("Invalid option. Please enter yes or no.")

    raise InvalidApprovalLimit(
        "Three invalid responses. Terminating."
    )


class InvalidApprovalLimit(Exception):
    pass


async def run_command(argv):
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=30,
        )

    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()

        return {
            "error": "Timeout; final effect may be unknown.",
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }

    return {
        "returncode": process.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


def assess_service(intent, result):
    if result.get("returncode") != 0:
        return {
            "status": "ERROR",
            "reason": "systemctl inspection failed.",
        }

    properties = {}

    for line in result["stdout"].splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value

    if properties.get("LoadState") != "loaded":
        return {
            "status": "INDETERMINATE",
            "reason": "Unit is missing or not loaded.",
            "properties": properties,
        }

    state = properties.get("ActiveState")

    if state == "active":
        status = "SATISFIED"
    elif state == "inactive":
        status = "SERVICE_INACTIVE"
    else:
        # Failed/activating/deactivating need separate handling.
        status = "INDETERMINATE"

    return {
        "status": status,
        "properties": properties,
    }


def assess_ufw(intent, result):
    if result.get("returncode") != 0:
        return {
            "status": "ERROR",
            "reason": "UFW inspection failed.",
        }

    output = result["stdout"]

    if re.search(r"^Status:\s+inactive\s*$", output, re.MULTILINE):
        return {"status": "FIREWALL_INACTIVE"}

    if not re.search(r"^Status:\s+active\s*$", output, re.MULTILINE):
        return {
            "status": "INDETERMINATE",
            "reason": "Unrecognized UFW status.",
        }

    expected_network = ipaddress.ip_network(intent.source_network)
    expected_destination = (
        f"{intent.destination_port}/{intent.protocol}"
    )

    found = False
    ambiguous = False
    in_rules = False

    for original_line in output.splitlines():
        line = original_line.strip()

        if re.match(r"^To\s+Action\s+From$", line):
            in_rules = True
            continue

        if not in_rules or not line or set(line) <= {"-", " "}:
            continue

        # Common UFW output separates columns with >=2 spaces.
        columns = re.split(r"\s{2,}", line)

        if len(columns) != 3:
            ambiguous = True
            continue

        destination, action, source = columns

        # Remove UFW comment text.
        source = source.split(" #", 1)[0].strip()

        if action.endswith(" OUT"):
            continue

        if action not in {"ALLOW IN", "DENY IN", "REJECT IN"}:
            ambiguous = True
            continue

        ipv6 = "(v6)" in destination
        destination = destination.replace("(v6)", "").strip()

        source = source.replace("(v6)", "").strip()

        if destination != expected_destination:
            # Port ranges, app profiles, interface-specific rules,
            # and "Anywhere" destinations are outside this parser.
            if not re.fullmatch(r"\d+/(tcp|udp)", destination):
                ambiguous = True
            continue

        try:
            if source == "Anywhere":
                network = ipaddress.ip_network(
                    "::/0" if ipv6 else "0.0.0.0/0"
                )
            else:
                network = ipaddress.ip_network(source, strict=True)

        except ValueError:
            ambiguous = True
            continue

        if network != expected_network:
            continue

        expected_action = (
            "ALLOW IN"
            if intent.rule_action == "allow"
            else "DENY IN"
        )

        if action == expected_action:
            found = True
        else:
            # A matching rule with the opposite action, including REJECT,
            # needs human review because UFW rule ordering can matter.
            ambiguous = True

    if ambiguous:
        return {
            "status": "INDETERMINATE",
            "reason": (
                "Unsupported or potentially conflicting UFW rules. "
                "No automatic repair will be proposed."
            ),
        }

    return {
        "status": "SATISFIED" if found else "MISSING_RULE",
        "scope": (
            "Exact supported UFW rule presence only; "
            "not end-to-end reachability."
        ),
    }


class Controller:
    def __init__(self):
        self.plans = {}
        self.observations = {}

    def list_intents(self):
        config = load_config()

        return {
            "intents": [
                intent.model_dump(exclude_none=True)
                for intent in config.intents
            ]
        }

    def prepare(self, intent_id, action):
        if action not in {"inspect", "repair"}:
            raise ValueError("Unsupported action.")

        config = load_config()
        intent = find_intent(config, intent_id)
        policy_hash = fingerprint(intent)

        if action == "repair":
            observation = self.observations.get(intent_id)

            if (
                not observation
                or observation["fingerprint"] != policy_hash
                or time.monotonic() - observation["observed_at"] > 120
            ):
                raise ValueError(
                    "A fresh inspection of this policy is required."
                )

            required_status = (
                "MISSING_RULE"
                if intent.type == "protected_ingress"
                else "SERVICE_INACTIVE"
            )

            if observation["assessment"]["status"] != required_status:
                raise ValueError(
                    "Current evidence does not support this repair."
                )

        if intent.type == "protected_ingress":
            if action == "inspect":
                argv = privileged(["ufw", "status", "verbose"])
                purpose = (
                    f"Inspect UFW for intent {intent.id}. Read-only."
                )
            else:
                argv = privileged([
                    "ufw", intent.rule_action, "in",
                    "proto", intent.protocol,
                    "from", intent.source_network,
                    "to", "any",
                    "port", str(intent.destination_port),
                ])
                purpose = (
                    f"Restore the exact {intent.rule_action} rule "
                    f"for {intent.id}. "
                    "No existing rules or default policies are removed."
                )

        else:
            if action == "inspect":
                argv = [
                    "systemctl", "show",
                    "--no-pager",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=SubState",
                    intent.unit,
                ]
                purpose = (
                    f"Inspect systemd state for {intent.unit}. Read-only."
                )
            else:
                argv = privileged([
                    "systemctl", "start", intent.unit,
                ])
                purpose = f"Start {intent.unit}."

        # Remove expired plans.
        timestamp = time.monotonic()

        self.plans = {
            key: value
            for key, value in self.plans.items()
            if value["expires_at"] > timestamp
        }

        plan_id = secrets.token_urlsafe(24)

        plan = {
            "plan_id": plan_id,
            "intent_id": intent.id,
            "action": action,
            "fingerprint": policy_hash,
            "purpose": purpose,
            "argv": argv,
            "command": shlex.join(argv),
            "expires_at": timestamp + 120,
        }

        self.plans[plan_id] = plan
        audit("plan_created", plan)

        return plan.copy()

    def discard(self, plan_id):
        self.plans.pop(plan_id, None)
        return {"discarded": True}

    async def execute(self, plan_id, scheduled=False):
        plan = self.plans.pop(plan_id, None)

        if not plan:
            raise ValueError("Unknown or consumed plan.")

        if time.monotonic() > plan["expires_at"]:
            raise ValueError("Plan expired. Prepare a new plan.")

        # Shared with the scheduler, preventing overlapping execution.
        with controller_lock():
            config = load_config()
            intent = find_intent(config, plan["intent_id"])

            if scheduled and not is_authorized(
                config,
                intent,
                plan["action"],
            ):
                raise ValueError(
                    "Scheduled authorization missing or revoked."
                )
            if fingerprint(intent) != plan["fingerprint"]:
                raise ValueError(
                    "Intent changed after planning. Plan cancelled."
                )

            if plan["action"] == "repair":
                observation = self.observations.get(intent.id)

                if (
                    not observation
                    or time.monotonic()
                    - observation["observed_at"] > 120
                    or observation["fingerprint"]
                    != plan["fingerprint"]
                ):
                    raise ValueError(
                        "Inspection evidence expired or changed."
                    )

                # Consume evidence before attempting a mutation.
                self.observations.pop(intent.id, None)

            # If audit persistence fails, do not run the command.
            audit("execution_started", plan)

            try:
                result = await run_command(plan["argv"])
            except OSError as error:
                result = {"error": str(error)}

            response = {
                "intent_id": intent.id,
                "action": plan["action"],
                "command": plan["command"],
                **result,
            }

            if plan["action"] == "inspect":
                if intent.type == "protected_ingress":
                    assessment = assess_ufw(intent, result)
                else:
                    assessment = assess_service(intent, result)

                observation = {
                    "fingerprint": plan["fingerprint"],
                    "observed_at": time.monotonic(),
                    "assessment": assessment,
                }

                self.observations[intent.id] = observation
                response["assessment"] = assessment

            else:
                response["verification_required"] = True

            audit("execution_result", response)
            return response
