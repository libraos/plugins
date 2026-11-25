# LibraOS Next plugins

The plugin catalogue LibraOS Next installs from, in **Settings → Plugins**.

`catalog.json` lists each plugin with the one commit that was reviewed. The app installs only that commit and checks every file, so a change here reaches users only after a new review updates the catalogue.

| Plugin | What it does |
|---|---|
| [Local redaction](plugins/redact) | Replaces names, contact details, ID numbers and credentials in a message and its attachments with placeholders before it is sent, on your own computer. Word documents and PDFs with a text layer go as redacted text. |
| [Outreach mailer](plugins/outreach) | Gives Claude Code and Codex agents the outreach mailer's tools for one project: search contacts, recipient histories and broadcasts, write and test-send a draft, and prepare a send for a person to confirm. It cannot send. Needs the `outreach` program on PATH. Not in the catalogue yet. |

A plugin is a folder with an `agentd-plugin.json` manifest. Its `before-send` hook is a command that reads one JSON object on stdin and prints one decision on stdout: pass, rewrite or block. Anything else stops the send.

A plugin may instead, or as well, carry MCP servers (`contributes.mcpServers`) that the Claude Code and Codex agents the app starts get while the plugin is on, with settings filled in Settings → Plugins; a secret setting reaches its server only as a file.

The plugins here are under the MIT licence (`LICENSE`). The redaction model, [veil-detect](https://huggingface.co/libraos/veil-detect), is under Apache-2.0 and is downloaded by the plugin's setup, not stored here.
