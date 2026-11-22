# Intent-Based Networking Assistant

Use the assistant to save a firewall intent, inspect Uncomplicated Firewall (UFW), and apply a missing ingress rule after reviewing and approving the command.

## Before you start

Use a Linux server with systemd, UFW, and Python 3.10 or later. From the project directory, set up a Python environment if you need one.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'mcp>=2,<3' 'pydantic>=2,<3' openai PyYAML
```

The assistant runs UFW through `sudo -n` when launched by a non-root user, so that account needs permission to run the relevant UFW commands without a password prompt.

## Step 1. Check the UFW service

Check the UFW systemd unit before changing the firewall. [systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)

```text
'''
systemctl status ufw.service
'''
```

## Step 2. Enable UFW

If you administer the server over SSH, make sure UFW allows your SSH connection before enabling it. Use `systemctl` to check the unit and look for `Status: active` in the UFW output to confirm that packet filtering is active. [UFW manual](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html)

```bash
sudo ufw enable
systemctl status ufw.service
sudo ufw status verbose
```

## Step 3. Review and add firewall rules manually

Review the current rules and the default incoming and outgoing policies.

```bash
sudo ufw status verbose
```

To allow incoming TCP traffic on port 8000 only from `10.0.0.1`, use a `/32` source. [UFW rule syntax](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html#RULE_SYNTAX)

```bash
sudo ufw allow in proto tcp from 10.0.0.1/32 to any port 8000
```

If port 8000 is intended to be public, the following rule allows inbound TCP traffic from any IPv4 source and also applies to IPv6 when enabled in UFW. Use the restricted rule on its own when access should be limited to `10.0.0.1`. [UFW manual](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html#NOTES)

```bash
sudo ufw allow in 8000/tcp
```

Use `0.0.0.0/0` explicitly for an IPv4-only rule matching the assistant's public ingress example.

```bash
sudo ufw allow in proto tcp from 0.0.0.0/0 to any port 8000
```

If your outgoing policy requires a rule, this example permits outbound TCP traffic to port 8000 on `10.0.0.1`. Configure egress manually in UFW. [UFW rule syntax](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html#RULE_SYNTAX)

```bash
sudo ufw allow out proto tcp to 10.0.0.1 port 8000
```

## Step 4. Run the assistant and enter an ingress prompt

Set `OPENAI_API_KEY` and `OPENAI_MODEL` in your shell. Choose a model that supports function calling, then start the assistant.

```bash
python ibn_assistant.py
```

For public IPv4 ingress, enter this prompt. If asked for a source CIDR, enter `0.0.0.0/0`.

> "Please add port 8000 to ingress traffic TCP."

For a rule restricted to one address, enter the following. If asked for a source CIDR, enter `10.0.0.1/32`.

> "Add 10.0.0.1 to ingress TCP via port 8000."

Both prompts request an allow rule for TCP port 8000. The assistant saves the desired rule to `intents.yaml` after approval and checks for the matching rule in UFW. If you already added it manually, the inspection can find it without adding it again.

### Sample intent configurations

Each example is a complete `intents.yaml`. Choose the source range that matches the access you want.

**Allow TCP port 8000 from `10.0.0.1` only**

```yaml
version: 1
intents:
  - id: example-ingress
    type: protected_ingress
    enabled: true
    source_network: 10.0.0.1/32
    destination_port: 8000
    protocol: tcp
    rule_action: allow
authorizations: []
```

**Allow TCP port 8000 from any IPv4 address**

```yaml
version: 1
intents:
  - id: example-public-ingress
    type: protected_ingress
    enabled: true
    source_network: 0.0.0.0/0
    destination_port: 8000
    protocol: tcp
    rule_action: allow
authorizations: []
```

## Step 5. Review each operation and approve it

The assistant uses a local Model Context Protocol (MCP) server. The CLI shows the proposed intent change or shell command before it proceeds. Review the operation and type `yes` to approve it or `no` to reject it and stop that workflow. Saving the intent, inspecting UFW, applying a repair, and verifying the result each require separate approval.

## Step 6. Read the JSON command result

After you approve a shell command, the assistant runs the displayed command and prints its result as JSON. The result includes `returncode`, `stdout`, and `stderr` when the process completes. Execution failures can also appear in an `error` field. An inspection includes an `assessment` of the firewall state.

## Step 7. Verify the UFW rule

The assistant proposes the following inspection before adding a rule and again after a successful repair.

```bash
sudo ufw status verbose
```

If the inspection reports `MISSING_RULE`, the assistant can propose the matching `ufw allow in` command for approval. After it runs successfully, approve the follow-up inspection. `SATISFIED` means the exact rule is present in UFW. If UFW is inactive or the result is unclear, review the firewall state manually. If the repair fails, review the JSON output before requesting another attempt.

## Step 8. Review the audit log

IBN logs approvals, intent updates made through the assistant, and command results in `audit.yaml` at the project root. Git ignores the file. Users with write access can edit it, and direct edits to `intents.yaml` fall outside the audit trail.

In Cisco Catalyst Center, **Activities > Audit Logs** shows system events, configuration changes, and who initiated them. [Cisco Administrator Guide](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-3-x/admin-guide/cisco-catalyst-center-admin-guide-3-3-x/manage-system-configurations/t_view_auditlogs.html)

This sample records a successful rule addition awaiting verification.

```yaml
---
timestamp: '2026-01-01T12:00:00+00:00'
event: execution_result
payload:
  intent_id: example-ingress
  action: repair
  command: sudo -n ufw allow in proto tcp from 10.0.0.1/32 to any port 8000
  returncode: 0
  stdout: "Rule added\n"
  stderr: ''
  verification_required: true
```
