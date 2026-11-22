# mcp_tools.py

from controller import Controller, audit
from intent_config import (
    Intent,
    load_config,
    save_config,
)


def register_tools(mcp):
    controller = Controller()

    @mcp.tool()
    def list_intents() -> dict:
        """
        Read desired-state intents from YAML after CLI approval.

        Does not inspect UFW or systemd.
        """
        result = controller.list_intents()

        audit("intent_configuration_read", {
            "count": len(result["intents"]),
        })

        return {
            **result,
            "source": "intents.yaml",
            "actual_state_checked": False,
        }

    @mcp.tool()
    def upsert_intent(intent: Intent) -> dict:
        """
        Add or update one desired-state intent after CLI approval.

        Replaces the intent with the same ID, or adds a new intent.
        Does not itself execute firewall or service commands.
        Firewall intents support exact allow and deny rules.
        Does not grant unattended authorization.
        """
        config = load_config()

        existing = next(
            (
                item
                for item in config.intents
                if item.id == intent.id
            ),
            None,
        )

        config.intents = [
            item
            for item in config.intents
            if item.id != intent.id
        ]
        config.intents.append(intent)

        # Validate the entire configuration, including duplicates.
        validated = type(config).model_validate(
            config.model_dump()
        )

        audit("intent_update_started", {
            "previous": (
                existing.model_dump(exclude_none=True)
                if existing else None
            ),
            "requested": intent.model_dump(exclude_none=True),
        })

        save_config(validated)

        # Read back the saved configuration.
        saved_config = load_config()
        saved = next(
            item
            for item in saved_config.intents
            if item.id == intent.id
        )

        if saved.model_dump() != intent.model_dump():
            raise RuntimeError(
                "Saved intent does not match the requested policy."
            )

        result = {
            "status": "updated" if existing else "created",
            "intent": saved.model_dump(exclude_none=True),
            "configuration_verified": True,
            "actual_state_checked": False,
            "system_changed": False,
            "message": (
                "Desired policy saved and read back successfully. "
                "UFW/systemd has not been inspected or modified."
            ),
        }

        audit("intent_update_completed", result)
        return result

    @mcp.tool()
    def propose_inspection(intent_id: str) -> dict:
        """
        Prepare an actual UFW or systemd inspection.
        Does not execute a command.
        Also used for post-repair verification.
        """
        return controller.prepare(intent_id, "inspect")

    @mcp.tool()
    def propose_repair(intent_id: str) -> dict:
        """
        Prepare repair based on fresh inspection evidence.
        Does not execute a command.
        """
        return controller.prepare(intent_id, "repair")

    @mcp.tool()
    async def execute_plan(plan_id: str) -> dict:
        """CLI-only execution after approval."""
        return await controller.execute(plan_id)

    @mcp.tool()
    def discard_plan(plan_id: str) -> dict:
        """Discard a plan without execution."""
        return controller.discard(plan_id)
