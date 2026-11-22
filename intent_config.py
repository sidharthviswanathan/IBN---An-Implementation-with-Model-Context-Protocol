# intent_config.py

import hashlib
import ipaddress
import json
import os
import re
import tempfile

from pathlib import Path
from typing import Literal

import yaml

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "intents.yaml"
AUDIT_PATH = BASE_DIR / "audit.yaml"

Action = Literal["inspect", "repair"]
FirewallRuleAction = Literal["allow", "deny"]


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str
    type: Literal["protected_ingress", "service_running"]
    enabled: bool = True

    source_network: str | None = None
    destination_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
    )
    protocol: Literal["tcp", "udp"] | None = None
    # Defaults to allow so existing configuration files remain valid.
    rule_action: FirewallRuleAction = "allow"

    unit: str | None = None

    @model_validator(mode="after")
    def validate_policy(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", self.id):
            raise ValueError("Invalid intent ID.")

        if self.type == "protected_ingress":
            if (
                self.source_network is None
                or self.destination_port is None
                or self.protocol is None
            ):
                raise ValueError(
                    "Firewall intent requires source_network, "
                    "destination_port, and protocol."
                )

            if self.unit is not None:
                raise ValueError("Firewall intent cannot specify unit.")

            network = ipaddress.ip_network(
                self.source_network,
                strict=True,
            )
            self.source_network = str(network)

        else:
            if not self.unit or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service",
                self.unit,
            ):
                raise ValueError(
                    "Service intent requires an explicit .service unit."
                )

            if any(
                value is not None
                for value in (
                    self.source_network,
                    self.destination_port,
                    self.protocol,
                )
            ):
                raise ValueError(
                    "Service intent cannot contain firewall fields."
                )

            if self.rule_action != "allow":
                raise ValueError(
                    "Service intent cannot specify a firewall action."
                )

        return self


class Authorization(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    intent_id: str
    fingerprint: str
    actions: list[Action]
    approved_at: str


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    intents: list[Intent]
    authorizations: list[Authorization] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique(self):
        ids = [intent.id for intent in self.intents]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate intent IDs.")

        policies = []

        for intent in self.intents:
            policy = intent.model_dump(
                exclude={"id", "enabled"},
                exclude_none=True,
            )
            policies.append(json.dumps(policy, sort_keys=True))

        if len(policies) != len(set(policies)):
            raise ValueError("Duplicate intent policies.")

        auth_ids = [
            authorization.intent_id
            for authorization in self.authorizations
        ]

        if len(auth_ids) != len(set(auth_ids)):
            raise ValueError("Duplicate authorization records.")

        for authorization in self.authorizations:
            if authorization.intent_id not in ids:
                raise ValueError(
                    "Authorization references an unknown intent."
                )

            if (
                "repair" in authorization.actions
                and "inspect" not in authorization.actions
            ):
                raise ValueError(
                    "Repair authorization also requires inspect."
                )

        return self


def ensure_config_exists():
    """Create an empty YAML configuration only if it is missing."""
    default_config = {
        "version": 1,
        "intents": [],
        "authorizations": [],
    }

    try:
        # Exclusive creation: never overwrite an existing file.
        with CONFIG_PATH.open("x", encoding="utf-8") as handle:
            yaml.safe_dump(
                default_config,
                handle,
                sort_keys=False,
            )
    except FileExistsError:
        pass

def load_config() -> Configuration:
    ensure_config_exists()
    with CONFIG_PATH.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)

    return Configuration.model_validate(document)


def fingerprint(intent: Intent) -> str:
    document = intent.model_dump(exclude_none=True)
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    return hashlib.sha256(encoded).hexdigest()


def find_intent(config: Configuration, intent_id: str) -> Intent:
    for intent in config.intents:
        if intent.id == intent_id:
            if not intent.enabled:
                raise ValueError("Intent is disabled.")
            return intent

    raise ValueError(f"Unknown intent: {intent_id}")


def is_authorized(
    config: Configuration,
    intent: Intent,
    action: str,
) -> bool:
    return any(
        authorization.intent_id == intent.id
        and authorization.fingerprint == fingerprint(intent)
        and action in authorization.actions
        for authorization in config.authorizations
    )


def save_config(config: Configuration):
    # Validate again before writing.
    validated = Configuration.model_validate(config.model_dump())

    document = validated.model_dump(exclude_none=True)

    fd, temporary = tempfile.mkstemp(
        prefix=".intents-",
        suffix=".yaml",
        dir=CONFIG_PATH.parent,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                document,
                handle,
                sort_keys=False,
            )
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, CONFIG_PATH)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
