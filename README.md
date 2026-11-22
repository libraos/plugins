# AgentD plugins

The plugin catalogue AgentD Next installs from: the Plugins section of the AgentD page.

`catalog.json` lists each plugin with the one commit that was reviewed. The app installs only that commit and checks every file, so a change here reaches users only after a new review updates the catalogue.

| Plugin | What it does |
|---|---|
| [Local redaction](plugins/redact) | Replaces names, contact details, ID numbers and credentials in a message with placeholders before it is sent, on your own computer. |

A plugin is a folder with an `agentd-plugin.json` manifest. Its `before-send` hook is a command that reads one JSON object on stdin and prints one decision on stdout: pass, rewrite or block. Anything else stops the send.

The plugins here are under the MIT licence (`LICENSE`). The redaction model, [veil-detect](https://huggingface.co/libraos/veil-detect), is under Apache-2.0 and is downloaded by the plugin's setup, not stored here.
