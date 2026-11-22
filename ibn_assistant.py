# ibn_assistant.py

import asyncio
import json
import logging
import os
import sys
import yaml

from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver import MCPServer

from openai import AsyncOpenAI

from controller import (
    InvalidApprovalLimit,
    ask_approval,
    audit,
)
from intent_config import Intent, load_config
from mcp_tools import register_tools


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

SCRIPT = Path(__file__).resolve()

# MCP 2.x: MCPServer replaces FastMCP.
mcp = MCPServer("local-intent-assistant")
register_tools(mcp)

# Only these tools are exposed to the model.
# Execution and discard remain application-controlled.
MODEL_TOOLS = {
    "list_intents",
    "upsert_intent",
    "propose_inspection",
    "propose_repair",
}

INSTRUCTIONS = """
You are a terminal server administration assistant.

Ordinary questions do not require tools.

Distinguish:
1. Desired configuration stored in YAML.
2. Actual firewall or service state observed through commands.

Configuration:
- Use list_intents to read configured intents.
- Use upsert_intent to add or update desired policy.
- The CLI asks approval before either operation.
- An update replaces the intent with the same ID.
- Ask for missing required details before proposing an intent.
- Firewall intents require an explicit source CIDR, port, protocol, and
  rule_action (allow or deny). Use 0.0.0.0/0 for all IPv4 sources.
- Infer deny when the user says block, and allow when the user says permit.
- Never assume unrestricted SSH access.
- TCP may be inferred when omitted, but disclose it.
- Service intents require an explicit systemd .service unit.
- Saving YAML does not apply policy or check the server.
- Never claim otherwise.
- Do not say conversational intent editing is unavailable.

Actual inspection:
- Use propose_inspection to check UFW or systemd.
- The CLI requests approval before executing the command.
- Report the returned assessment, including uncertainty.
- UFW rule presence is not proof of reachability.
- An active systemd unit is not proof of application health.

Repair:
- Inspect first.
- Use propose_repair only with supporting fresh evidence.
- After successful repair, propose another inspection.
- Inspection, repair, and verification require separate approvals.
- Never enable UFW, flush rules, remove unrelated rules,
  or invent shell commands.

After saving a firewall intent, inspect UFW and, if the exact rule is
missing, propose a repair, then propose verification. Each command needs
its own approval. Do not repair when inspection is inactive or indeterminate.

On rejection, acknowledge and stop that workflow.
On errors or timeouts, do not retry automatically.
Never claim execution succeeded without tool evidence.

Use upsert_intent when the user asks to create or update an intent.
Ask for missing required details.
The application requests approval before saving.
Saving an intent does not itself apply firewall policy; follow it with the
approved inspection and repair workflow.
"""

def approve_operation(operation_name, proposal):
    try:
        approved = ask_approval(proposal)

    except (InvalidApprovalLimit, EOFError, KeyboardInterrupt):
        audit("operation_approval_aborted", {
            "operation": operation_name,
        })
        raise

    audit("operation_approval", {
        "operation": operation_name,
        "approved": approved,
    })

    return approved
# ---------------------------------------------------------
# MCP response handling
# ---------------------------------------------------------

def unpack_mcp_result(result):
    """
    Decode an MCP 2.x CallToolResult.

    MCP 2.x uses:
        is_error
        structured_content
    """
    texts = [
        block.text
        for block in result.content
        if getattr(block, "type", None) == "text"
    ]

    text = "\n".join(texts)

    if result.is_error:
        raise RuntimeError(text or "MCP tool failed.")

    if result.structured_content is not None:
        return result.structured_content

    if not text:
        raise RuntimeError("MCP tool returned no result.")

    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"MCP tool returned invalid JSON: {text}"
        ) from error


async def call_mcp(session, name, arguments):
    response = await session.call_tool(
        name,
        arguments=arguments,
    )

    result = unpack_mcp_result(response)

    if not isinstance(result, dict):
        raise RuntimeError(
            f"MCP tool {name!r} returned a non-object result."
        )

    return result


# ---------------------------------------------------------
# Approval and execution
# ---------------------------------------------------------

async def discard_pending_plan(session, plan_id):
    """
    Attempt cleanup without hiding the original cancellation.
    No operating-system command is executed by discard_plan.
    """
    try:
        await call_mcp(
            session,
            "discard_plan",
            {"plan_id": plan_id},
        )
    except Exception as error:
        print(
            f"\nWarning: could not discard pending plan: {error}",
            file=sys.stderr,
        )


async def handle_tool(session, name, raw_arguments):
    if name not in MODEL_TOOLS:
        return {"error": "Unsupported model tool."}

    try:
        arguments = json.loads(raw_arguments)

        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be an object.")

        if name == "list_intents":
            if arguments:
                raise ValueError(
                    "list_intents does not accept arguments."
                )

            proposal = {
                "purpose": "Read configured desired-state intents.",
                "operation": (
                    "Read intents.yaml.\n"
                    "This does not inspect the running firewall "
                    "or services."
                ),
            }

        elif name == "upsert_intent":
            if set(arguments) != {"intent"}:
                raise ValueError(
                    "upsert_intent requires only an intent argument."
                )

            intent = Intent.model_validate(arguments["intent"])

            arguments = {
                "intent": intent.model_dump(exclude_none=True),
            }

            proposal = {
                "purpose": (
                    "Add a desired-state intent, or replace the "
                    "existing intent with the same ID."
                ),
                "operation": (
                    "Write this intent to intents.yaml:\n\n"
                    + yaml.safe_dump(
                        arguments["intent"],
                        sort_keys=False,
                    )
                    + "\nNo firewall or service command will run.\n"
                    "No unattended authorization will be granted."
                ),
            }

        else:
            proposal = None

    except Exception as error:
        return {"error": str(error)}

    # Configuration operations require approval before the MCP call.
    if proposal is not None:
        if not approve_operation(name, proposal):
            return {
                "status": "rejected",
                "message": "User rejected the configuration operation.",
            }

        try:
            result = await call_mcp(session, name, arguments)
        except Exception as error:
            result = {"error": str(error)}

        print("\nConfiguration result:")
        print(json.dumps(result, indent=2))

        return result

    # Preparing a command does not execute it.
    try:
        plan = await call_mcp(session, name, arguments)
    except Exception as error:
        return {"error": str(error)}

    try:
        approved = approve_operation(name, plan)

    except (InvalidApprovalLimit, EOFError, KeyboardInterrupt):
        await call_mcp(
            session,
            "discard_plan",
            {"plan_id": plan["plan_id"]},
        )
        raise

    if not approved:
        await call_mcp(
            session,
            "discard_plan",
            {"plan_id": plan["plan_id"]},
        )

        return {
            "status": "rejected",
            "message": "User rejected the command.",
        }

    try:
        result = await call_mcp(
            session,
            "execute_plan",
            {"plan_id": plan["plan_id"]},
        )
    except Exception as error:
        result = {"error": str(error)}

    print("\nCommand result:")
    print(json.dumps(result, indent=2))

    return result


# ---------------------------------------------------------
# OpenAI conversation
# ---------------------------------------------------------

async def run_conversation(session):
    # Avoid printing the HTTP client's successful OpenAI request logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    model = os.environ.get("OPENAI_MODEL")

    if not model:
        raise RuntimeError(
            "Set OPENAI_MODEL before running the application."
        )

    discovered = await session.list_tools()

    # MCP 2.x uses tool.input_schema.
    tools = [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.input_schema,
        }
        for tool in discovered.tools
        if tool.name in MODEL_TOOLS
    ]

    available_names = {
        tool.name
        for tool in discovered.tools
    }

    missing = MODEL_TOOLS - available_names

    if missing:
        raise RuntimeError(
            "Required MCP tools were not registered: "
            + ", ".join(sorted(missing))
        )

    history = []

    async with AsyncOpenAI() as client:
        print("Welcome. How may I assist?")
        print("Type 'exit' or 'quit' to finish.")

        while True:
            user_text = input("\n-> ").strip()

            if user_text.lower() in {"exit", "quit"}:
                return

            if not user_text:
                continue

            history.append({
                "role": "user",
                "content": user_text,
            })

            # Rejection applies only to this user request.
            workflow_rejected = False

            for _ in range(12):
                response = await client.responses.create(
                    model=model,
                    instructions=INSTRUCTIONS,
                    input=history,
                    tools=tools,
                    tool_choice=(
                        "none"
                        if workflow_rejected
                        else "auto"
                    ),
                    parallel_tool_calls=False,
                )

                history.extend(response.output)

                if response.output_text:
                    print(
                        f"\nAssistant: {response.output_text}"
                    )

                calls = [
                    item
                    for item in response.output
                    if item.type == "function_call"
                ]

                if not calls:
                    break

                for call in calls:
                    if workflow_rejected:
                        result = {
                            "status": "rejected",
                            "message": (
                                "This workflow was cancelled. "
                                "No further tools may run until "
                                "a new user message."
                            ),
                        }
                    else:
                        result = await handle_tool(
                            session,
                            call.name,
                            call.arguments,
                        )

                    if result.get("status") == "rejected":
                        workflow_rejected = True

                    history.append({
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": json.dumps(result),
                    })

            else:
                print(
                    "\nTool round limit reached. "
                    "Ending this session."
                )
                return


# ---------------------------------------------------------
# CLI startup
# ---------------------------------------------------------

async def run_cli():
    # Validate configuration before starting MCP or inference.
    load_config()

    # Explicit environment avoids passing OpenAI credentials
    # into the networking MCP subprocess.
    child_env = {
        "PATH": os.environ.get(
            "PATH",
            (
                "/usr/local/sbin:/usr/local/bin:"
                "/usr/sbin:/usr/bin:/sbin:/bin"
            ),
        ),
    }

    # Preserve basic runtime environment where present.
    for key in (
        "HOME",
        "LANG",
        "LC_ALL",
        "VIRTUAL_ENV",
        "SYSTEMD_BUS_ADDRESS",
        "DBUS_SYSTEM_BUS_ADDRESS",
    ):
        if key in os.environ:
            child_env[key] = os.environ[key]

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            str(SCRIPT),
            "--mcp-server",
        ],
        env=child_env,
    )

    async with stdio_client(parameters) as (
        read_stream,
        write_stream,
    ):
        async with ClientSession(
            read_stream,
            write_stream,
        ) as session:
            await session.initialize()
            await run_conversation(session)


# ---------------------------------------------------------
# Entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    if "--mcp-server" in sys.argv:
        # Never print terminal UI text here.
        # stdout is reserved for the MCP stdio protocol.
        mcp.run(transport="stdio")

    else:
        try:
            asyncio.run(run_cli())

        except (
            InvalidApprovalLimit,
            EOFError,
            KeyboardInterrupt,
        ):
            print(
                "\nSession ended. "
                "No further command will execute."
            )
