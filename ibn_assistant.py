import asyncio
import ipaddress
import json
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver import MCPServer
from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

SCRIPT = Path(__file__).resolve()
DB_PATH = SCRIPT.with_name("ibn_audit.sqlite3")

mcp = MCPServer("local-network-assistant")


# Plans exist only in the MCP server process.
PENDING_PLANS = {}


SYSTEM_INSTRUCTIONS = """
You are a server administration assistant in a terminal.

For ordinary questions, respond normally without using tools.

For firewall requests:
- Use the available proposal tools when appropriate.
- A proposal does not execute a command.
- The application separately asks the user for approval.
- Never claim a change was made unless execution succeeded.
- If a request is ambiguous, ask a clarification question.
- For inbound access, default the destination to this server.
- Default the protocol to TCP when omitted, but explicitly state
  that interpretation in your response or proposal.
- Before the first firewall modification in a conversation,
  propose checking UFW status.
- If UFW is inactive, do not propose enabling it or pretend that
  adding a rule provides active protection.
- If a command is rejected, acknowledge the rejection and stop
  that workflow. Do not immediately propose another command.
- A successful UFW command is not proof of end-to-end connectivity.
- Do not claim to inspect services, open ports, or cloud firewall
  rules: this version does not have those tools.
- Do not try to bypass the supported tools using shell commands.
"""


# ---------------------------------------------------------
# Input schemas
# ---------------------------------------------------------

class StatusArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AllowArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(
        description="One IPv4 or IPv6 source address, without a CIDR suffix."
    )
    destination_port: int = Field(ge=1, le=65535)
    protocol: str = Field(
        pattern="^(tcp|udp)$",
        description="Transport protocol: tcp or udp.",
    )


# ---------------------------------------------------------
# SQLite audit
# ---------------------------------------------------------

def initialize_database():
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)


def audit(event_type, payload):
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO audit_events(timestamp, event_type, payload)
            VALUES (?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_type,
                json.dumps(payload),
            ),
        )


# ---------------------------------------------------------
# MCP server: prepare plans without running commands
# ---------------------------------------------------------

def privileged_command(arguments):
    if os.geteuid() == 0:
        return arguments

    # Never block on an unexpected interactive sudo password prompt.
    return ["sudo", "-n", *arguments]


def create_plan(purpose, arguments):
    import shlex

    plan_id = secrets.token_urlsafe(24)

    plan = {
        "plan_id": plan_id,
        "purpose": purpose,
        "argv": privileged_command(arguments),
    }
    plan["command"] = shlex.join(plan["argv"])

    PENDING_PLANS[plan_id] = plan
    return plan


@mcp.tool()
def propose_ufw_status() -> dict:
    """Prepare a read-only UFW status check. Does not execute it."""
    return create_plan(
        "Inspect UFW status and default policies. Read-only operation.",
        ["ufw", "status", "verbose"],
    )


@mcp.tool()
def propose_ufw_allow_inbound(
    source_ip: str,
    destination_port: int,
    protocol: str,
) -> dict:
    """Prepare an inbound UFW allow rule. Does not execute it."""
    arguments = AllowArguments(
        source_ip=source_ip,
        destination_port=destination_port,
        protocol=protocol,
    )

    # Reject arbitrary text, ranges, and shell syntax.
    address = str(ipaddress.ip_address(arguments.source_ip))

    return create_plan(
        (
            f"Allow incoming {arguments.protocol.upper()} traffic "
            f"from {address} to destination port "
            f"{arguments.destination_port} on this server. "
            "Existing default policies will not be changed."
        ),
        [
            "ufw",
            "allow",
            "in",
            "proto",
            arguments.protocol,
            "from",
            address,
            "to",
            "any",
            "port",
            str(arguments.destination_port),
        ],
    )


@mcp.tool()
async def execute_plan(plan_id: str) -> dict:
    """Execute a pending plan. Called only by the CLI after approval."""
    # One-use plan: it cannot be executed twice.
    plan = PENDING_PLANS.pop(plan_id, None)

    if plan is None:
        return {"error": "Unknown, expired, or already consumed plan."}

    try:
        process = await asyncio.create_subprocess_exec(
            *plan["argv"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Prevent commands from asking additional terminal questions.
            stdin=asyncio.subprocess.DEVNULL,
            env={**os.environ, "LC_ALL": "C"},
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
                "command": plan["command"],
                "error": (
                    "Command timed out. Its final effect is unknown; "
                    "inspect state before retrying."
                ),
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }

        return {
            "command": plan["command"],
            "returncode": process.returncode,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }

    except OSError as error:
        return {
            "command": plan["command"],
            "error": str(error),
        }


@mcp.tool()
def discard_plan(plan_id: str) -> dict:
    """Discard a pending plan without executing it."""
    PENDING_PLANS.pop(plan_id, None)
    return {"discarded": True}


# ---------------------------------------------------------
# CLI approval and MCP response handling
# ---------------------------------------------------------

class InvalidApprovalLimit(Exception):
    pass


def ask_approval(plan):
    print("\nTool use")
    print(f"\nPurpose:\n{plan['purpose']}")
    print(f"\nCommand:\n{plan['command']}")

    for attempt in range(1, 4):
        answer = input(
            "\nDo you want to run this? (yes/no)\n-> "
        ).strip().lower()

        if answer == "yes":
            return True

        if answer == "no":
            return False

        if attempt < 3:
            print("Invalid option. Please enter yes or no.")
        else:
            print("Invalid option. Three invalid responses. Exiting.")
            raise InvalidApprovalLimit()


def unpack_mcp_result(result):
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

    return json.loads(text)


async def call_mcp(session, name, arguments):
    result = await session.call_tool(name, arguments=arguments)
    return unpack_mcp_result(result)


async def handle_proposal(session, tool_name, raw_arguments):
    validators = {
        "propose_ufw_status": StatusArguments,
        "propose_ufw_allow_inbound": AllowArguments,
    }

    if tool_name not in validators:
        return {"error": "Unsupported tool."}

    try:
        validated = validators[tool_name].model_validate_json(
            raw_arguments
        ).model_dump()

        plan = await call_mcp(session, tool_name, validated)
    except Exception as error:
        audit("proposal_error", {"error": str(error)})
        return {"error": str(error)}

    # Persist before offering execution.
    audit("plan_created", plan)

    try:
        approved = ask_approval(plan)
    except (InvalidApprovalLimit, EOFError, KeyboardInterrupt):
        await call_mcp(
            session,
            "discard_plan",
            {"plan_id": plan["plan_id"]},
        )
        audit("approval_aborted", {"plan_id": plan["plan_id"]})
        raise

    audit(
        "approval",
        {"plan_id": plan["plan_id"], "approved": approved},
    )

    if not approved:
        await call_mcp(
            session,
            "discard_plan",
            {"plan_id": plan["plan_id"]},
        )
        return {"status": "rejected", "message": "User rejected command."}

    # Execution is an application decision, not a model tool call.
    result = await call_mcp(
        session,
        "execute_plan",
        {"plan_id": plan["plan_id"]},
    )

    audit("execution_result", result)

    print("\nCommand result:")
    print(json.dumps(result, indent=2))

    return result


# ---------------------------------------------------------
# OpenAI conversation loop
# ---------------------------------------------------------

async def run_conversation(session):
    model = os.environ.get("OPENAI_MODEL")
    if not model:
        raise RuntimeError("Set OPENAI_MODEL before running the application.")

    # Discover the tools from MCP, but expose only proposal tools
    # to the model. Never expose execute_plan.
    discovered = await session.list_tools()
    permitted_names = {
        "propose_ufw_status",
        "propose_ufw_allow_inbound",
    }

    tools = [
        {
            "type": "function",
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.input_schema,
        }
        for tool in discovered.tools
        if tool.name in permitted_names
    ]

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

            audit("user_message", {"text": user_text})
            history.append({"role": "user", "content": user_text})

            # Bound the number of model/tool rounds per user request.
            for _ in range(10):
                response = await client.responses.create(
                    model=model,
                    instructions=SYSTEM_INSTRUCTIONS,
                    input=history,
                    tools=tools,
                    parallel_tool_calls=False,
                )

                history.extend(response.output)

                if response.output_text:
                    print(f"\nAssistant: {response.output_text}")
                    audit(
                        "assistant_message",
                        {"text": response.output_text},
                    )

                calls = [
                    item
                    for item in response.output
                    if item.type == "function_call"
                ]

                if not calls:
                    break

                for call in calls:
                    result = await handle_proposal(
                        session,
                        call.name,
                        call.arguments,
                    )

                    history.append({
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": json.dumps(result),
                    })
            else:
                print("Tool round limit reached. Ending this session.")
                return


async def run_cli():
    initialize_database()

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(SCRIPT), "--mcp-server"],
        # The MCP subprocess does not need the OpenAI API key.
        env={
            key: value
            for key, value in os.environ.items()
            if key != "OPENAI_API_KEY"
        },
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            await run_conversation(session)


if __name__ == "__main__":
    if "--mcp-server" in sys.argv:
        # Never print terminal UI text in this mode:
        # stdout is reserved for the MCP protocol.
        mcp.run(transport="stdio")
    else:
        try:
            asyncio.run(run_cli())
        except (InvalidApprovalLimit, EOFError, KeyboardInterrupt):
            print("\nSession ended. No pending command will be executed.")
