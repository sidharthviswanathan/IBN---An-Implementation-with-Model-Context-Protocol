# reconcile.py

import argparse
import asyncio
import fcntl

from controller import (
    Controller,
    InvalidApprovalLimit,
    ask_approval,
    audit,
    controller_lock,
    now,
)
from intent_config import (
    Authorization,
    BASE_DIR,
    find_intent,
    fingerprint,
    is_authorized,
    load_config,
    save_config,
)


def authorize(intent_id, repair):
    config = load_config()
    intent = find_intent(config, intent_id)
    original_hash = fingerprint(intent)

    actions = ["inspect"]

    if repair:
        actions.append("repair")

    if intent.type == "protected_ingress":
        repair_description = (
            f"Restore only the exact missing UFW {intent.rule_action} rule. "
            "Never enable UFW or remove existing rules."
        )
    else:
        repair_description = (
            f"Start {intent.unit} only when inspection reports inactive. "
            "Do not restart failed or active units."
        )

    proposal = {
        "purpose": (
            "Grant standing permission for scheduled operations. "
            "These commands will not prompt on every cron run."
        ),
        "operation": (
            f"Intent: {intent.id}\n"
            f"Policy fingerprint: {original_hash}\n"
            f"Allowed actions: {', '.join(actions)}\n"
            + (
                repair_description
                if repair
                else "Inspection only; no repair."
            )
        ),
    }

    if not ask_approval(proposal):
        print("Authorization rejected.")
        return

    with controller_lock():
        # Reload to avoid authorizing a policy changed during approval.
        config = load_config()
        intent = find_intent(config, intent_id)

        if fingerprint(intent) != original_hash:
            raise ValueError(
                "Intent changed during approval. Try again."
            )

        config.authorizations = [
            item
            for item in config.authorizations
            if item.intent_id != intent_id
        ]

        config.authorizations.append(
            Authorization(
                intent_id=intent_id,
                fingerprint=original_hash,
                actions=actions,
                approved_at=now(),
            )
        )

        audit("authorization_granted", {
            "intent_id": intent_id,
            "fingerprint": original_hash,
            "actions": actions,
        })

        save_config(config)

    print("Standing authorization saved.")


def revoke(intent_id):
    proposal = {
        "purpose": "Revoke unattended permission for this intent.",
        "operation": f"Remove authorization for {intent_id}.",
    }

    if not ask_approval(proposal):
        print("Revocation cancelled.")
        return

    with controller_lock():
        config = load_config()

        config.authorizations = [
            item
            for item in config.authorizations
            if item.intent_id != intent_id
        ]

        save_config(config)

        audit("authorization_revoked", {
            "intent_id": intent_id,
        })

    print("Authorization revoked.")


async def authorized_execution(
    controller,
    intent_id,
    expected_fingerprint,
    action,
):
    # Serialize authorization checks and execution using the same lock.
    # Controller.execute also takes that lock, so perform this check
    # immediately before calling it, without nesting lock scopes.
    config = load_config()
    intent = find_intent(config, intent_id)

    if fingerprint(intent) != expected_fingerprint:
        raise ValueError("Policy changed during scheduled run.")

    if not is_authorized(config, intent, action):
        raise ValueError(f"No valid authorization for {action}.")

    plan = controller.prepare(intent_id, action)

    # Controller.execute rechecks the intent fingerprint.
    return await controller.execute(
        plan["plan_id"],
        scheduled=True,
    )


async def scheduled_run():
    # Separate scheduler lock prevents overlapping cron invocations.
    lock_path = BASE_DIR / ".scheduler.lock"

    with lock_path.open("a") as lock:
        try:
            fcntl.flock(
                lock,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            print("Another scheduled run is active. Skipping.")
            return

        config = load_config()
        controller = Controller()

        for intent in config.intents:
            if not intent.enabled:
                continue

            if not is_authorized(config, intent, "inspect"):
                audit("scheduled_skip", {
                    "intent_id": intent.id,
                    "reason": "No matching inspection authorization.",
                })
                continue

            policy_hash = fingerprint(intent)

            try:
                inspection = await authorized_execution(
                    controller,
                    intent.id,
                    policy_hash,
                    "inspect",
                )

                status = inspection["assessment"]["status"]
                print(f"{intent.id}: {status}")

                repairable = status in {
                    "MISSING_RULE",
                    "SERVICE_INACTIVE",
                }

                current = load_config()
                current_intent = find_intent(current, intent.id)

                if (
                    not repairable
                    or not is_authorized(
                        current,
                        current_intent,
                        "repair",
                    )
                ):
                    continue

                repair_result = await authorized_execution(
                    controller,
                    intent.id,
                    policy_hash,
                    "repair",
                )

                if repair_result.get("returncode") != 0:
                    audit("scheduled_repair_failed", repair_result)
                    continue

                verification = await authorized_execution(
                    controller,
                    intent.id,
                    policy_hash,
                    "inspect",
                )

                print(
                    f"{intent.id}: verification "
                    f"{verification['assessment']['status']}"
                )

            except Exception as error:
                audit("scheduled_error", {
                    "intent_id": intent.id,
                    "error": str(error),
                })
                print(f"{intent.id}: ERROR: {error}")


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--scheduled", action="store_true")
    group.add_argument("--authorize", metavar="INTENT_ID")
    group.add_argument("--revoke", metavar="INTENT_ID")

    parser.add_argument(
        "--repair",
        action="store_true",
        help="Also authorize unattended repair.",
    )

    args = parser.parse_args()

    if args.repair and not args.authorize:
        parser.error("--repair requires --authorize.")

    if args.authorize:
        authorize(args.authorize, args.repair)

    elif args.revoke:
        revoke(args.revoke)

    else:
        asyncio.run(scheduled_run())


if __name__ == "__main__":
    try:
        main()

    except (InvalidApprovalLimit, EOFError, KeyboardInterrupt):
        print("\nCancelled.")
