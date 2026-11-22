# Local redaction

Replaces names, organizations, places, contact details, ID numbers, financial and credential strings and dates in a message and its text attachments with placeholders such as `[PERSON_1]` before the message goes to the agent. You see the change and confirm or edit it before it is sent.

Detection runs on the computer that runs AgentD Next (with a remote or mobile client, that is the server, not your phone), with the [veil-detect](https://huggingface.co/libraos/veil-detect) v1.0.0 model and rules for e-mail addresses, phone numbers, API keys and tokens, Chinese ID card numbers and unified social credit codes.

## Set up

Needs Python 3.10 or newer and about 2 GB of disk. On the computer that runs AgentD Next:

```
python3 <plugin folder>/setup_env.py
```

It creates a Python environment with CPU torch and transformers in the plugin's data folder (`plugins/data/redact` in AgentD Next's data folder), downloads the model and checks it. Until it has run, every message is stopped with a reason that names the command. Run it again to repair a damaged download.

## What to know

- Redaction can miss sensitive details. Read the change before you send it.
- A value found anywhere in the message is replaced everywhere in it, in the text and every attachment; for a name, each part of three or more letters is replaced on its own too.
- It covers the messages you send from the composer: the text and UTF-8 text files up to 1 MB. A message with an image or another file is stopped; remove the file or paste its text. What agents read from your files, tool output and workspace context is not covered.
- One message can hold up to 100,000 characters; split longer ones.
- The original text and the placeholder map are kept only in memory while the message is checked. Placeholders are not turned back into the original values.
