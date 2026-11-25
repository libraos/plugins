# Outreach mailer

Gives the Claude Code and Codex agents LibraOS Next starts the [outreach](https://github.com/libraos/outreach) mailer's MCP server: they can search one project's contacts, recipient histories, broadcasts and suppressions, write, edit and test-send a draft, and prepare a send for a person to confirm. **They cannot send.** Other agents do not get the server; the plugin page says so.

The plugin has no hook and does not touch your messages. It holds only a manifest that tells LibraOS Next to start `outreach mcp`, and a setup step that checks the program is there. The server's full documentation is [docs/mcp.md](https://github.com/libraos/outreach/blob/main/docs/mcp.md) in the outreach repository.

## Install

1. **Install the `outreach` program.** The plugin does not ship it. Build it from the outreach repository (needs Go 1.22 or newer):

   ```sh
   git clone https://github.com/libraos/outreach
   cd outreach/shim && go build -o outreach ./cmd/outreach
   install -m 755 outreach ~/.local/bin/outreach   # or any folder on your PATH
   ```

   It must be on the `PATH` of the program that runs LibraOS Next (with a remote or mobile client, that is the server, not your phone). A desktop app started from the dock or a menu may not see the folders your shell adds to `PATH`, so pick a folder it sees, or start LibraOS Next from a shell; restart it after installing.
2. **Install the plugin** in Settings → Plugins and choose **Set up**. Setup runs `outreach --version` and nothing else: it downloads nothing and needs Python 3. If it fails, its message says what to fix; fix it and choose **Set up again**. (Builds of outreach without `--version` print their usage instead; setup accepts that when the usage lists `outreach mcp`.)
3. **Fill in the settings** below and turn the plugin on for the projects whose agents should have it.

## Settings

| Setting | Secret | Given to the server as |
|---|---|---|
| **Outreach URL** (`outreach_url`) | no | `OUTREACH_URL`: the service's base URL, such as `https://outreach.example.test`. Use https anywhere but this computer; the server warns at start when it is plain http to another host. |
| **Project API token** (`outreach_token`) | yes | `OUTREACH_API_KEY_FILE`: the path of a file holding the token. |

The token is an API token an Admin creates on the outreach console's Tokens screen. LibraOS Next keeps it in its secret store, never in the plugin's settings file, and gives it to the server only as a file readable by your user (written at each launch), so it is in no agent's command line, configuration or log. The server sends it only to the Outreach URL and never puts it in a tool result, an error or a log line.

Until both settings have a value the server is not given to agents, and the plugin page says which one is missing.

## The tools

All of them act in the token's project. Lists are paged (at most 50 a page, 500 in all) and every result is capped at 16 KB: search is search, not export.

| Tool | What it does | Viewer | Sender | Importer |
|---|---|:-:|:-:|:-:|
| `project_info` | The project and the token's role; the mailboxes, templates and staff test inboxes a draft may use | ✓ | ✓ | ✓ |
| `search_broadcasts` | Broadcasts by subject or body text, sender, status or date | ✓ | ✓ | ✓ |
| `broadcast_status` | One broadcast: state, content, last test, delivery counts | ✓ | ✓ | ✓ |
| `broadcast_report` | A broadcast's report and the recipients it did not reach | ✓ (addresses masked) | ✓ | ✓ |
| `search_contacts` | Contacts by address, domain or name, with status, lists, consent and suppression | | ✓ | ✓ |
| `recipient_history` | Whether an address received each broadcast, and if not, why | | ✓ | ✓ |
| `suppression_lookup` | Whether one address may be mailed, is suppressed or was erased | | ✓ | ✓ |
| `create_draft` | A new draft from a mailbox and a template of the project | | ✓ | |
| `edit_draft` | Change a draft that has not started | | ✓ | |
| `test_send` | Send a draft to some of the project's staff test inboxes, nowhere else | | ✓ | |
| `prepare_send` | What the confirmation would show (audience, exclusions, sender, subject, time) and the console link where a person confirms; changes nothing | | ✓ | |

A blank cell is a tool the service refuses for that role. Each exact-address lookup is audited in outreach as in the console.

## What it cannot do

No tool sends, schedules, pauses, resumes or cancels a broadcast, imports contacts, adds or lifts a suppression, exports or erases contacts, or manages members and tokens. A send reaches real people and cannot be taken back, so a person confirms every send in outreach; `prepare_send` gives the agent what that confirmation shows without the power to confirm. This holds in the tool list, in the server's HTTP client, which refuses every write except the three draft calls, and in the service, which checks the token's role on every call. A token never holds the Admin role, so an agent cannot widen its own access.

## One token, one project, least role

- **One token is one project.** The tools take no project; the project is the token's. This plugin carries one server and one token. To give agents a second project, make a second token and register a second server yourself under another name (such as `outreach-beta`), as [docs/mcp.md](https://github.com/libraos/outreach/blob/main/docs/mcp.md) shows.
- **Give the token the least role the agents need:** Viewer to report on broadcasts, Sender to draft and test. An Importer token adds contact lookups but no drafts, and there is no reason to give one to an agent.
- Text in contacts, subjects and bodies is written by other people and reaches the agent; it can carry instructions. No tool can send or widen access whatever the agent is talked into, but keep `create_draft`, `edit_draft` and `test_send` asking for permission where a person is watching (they ask as any MCP tool does under the thread's permission mode). What an agent writes into a draft reaches the staff test inboxes on `test_send`.
- Revoking the token on the Tokens screen stops the server at its next call.

## What to know

- The servers a thread gets are fixed when its agent starts or resumes: turning the plugin on or off, or changing a setting, reaches a running thread at its next resume or message.
- With every app MCP capability turned off (no task, browser or device tools) a thread has no MCP session, and this server is not attached either.
- The server runs as your user on the computer that runs LibraOS Next and needs network access to the Outreach URL.

## Catalogue

This plugin is not in `catalog.json` yet. Its entry, with the reviewed commit, is added at review after this folder is merged; until then it cannot be installed from Settings → Plugins.

## Tests

```sh
python3 -m unittest discover -s plugins/outreach/tests
```

They check the setup step with fake `outreach` programs (missing, with `--version`, without it, without `mcp`, failing) and the manifest's server and settings. The catalogue's manifest check is `scripts/check-plugin-manifest.ts plugins/outreach` in LibraOS Next.
