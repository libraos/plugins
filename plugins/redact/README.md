# Local redaction

Replaces names, organizations, places, contact details, ID numbers, financial and credential strings and dates in a message and its attachments (text files, Word documents and PDFs) with placeholders such as `[PERSON_1]` before the message goes to the agent. You see the change and confirm or edit it before it is sent.

Detection runs on the computer that runs AgentD Next (with a remote or mobile client, that is the server, not your phone), with the [veil-detect](https://huggingface.co/libraos/veil-detect) v1.0.0 model and rules for e-mail addresses, phone numbers, API keys and tokens, Chinese ID card numbers and unified social credit codes, and for details in legal documents:

| Placeholder                | What it covers                                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `[CASE_NUMBER_n]`          | Chinese court case numbers, such as （2024）京0105民初12345号                                                                      |
| `[BANK_ACCOUNT_n]`         | A number after 账号, 账户, 卡号 or "account no."; on its own, a 16 to 19 digit card number that passes the Luhn check              |
| `[IBAN_n]`                 | IBANs that pass the mod-97 check                                                                                                   |
| `[AMOUNT_n]`               | Amounts with a currency, in figures (人民币500,000.00元, 50万元, ¥1,234.5, USD 2,000,000) or Chinese capital numerals (伍拾万元整) |
| `[PLATE_n]`                | Mainland China vehicle plates, including new-energy plates                                                                         |
| `[LAWYER_LICENCE_n]`       | 17-digit lawyer licence numbers                                                                                                    |
| `[PROPERTY_CERTIFICATE_n]` | Real estate title certificate numbers, old and new formats                                                                         |

Where a rule and the model find the same text, the rule's placeholder is used.

On three synthetic Chinese legal texts (a judgment excerpt, a contract clause and a lawyer's letter; 1,625 characters, 45 details that must be replaced, every name and number invented), the plugin missed 0 of the 45 and replaced 1 of 71 spans wrongly (a single character taken for a name). Without the legal-document rules it missed 9, all of them amounts; the model already found the case, account, plate, licence and certificate numbers there, under its generic labels. The set is small and was written alongside the rules, so expect more misses on real documents. The texts and the script that measures them are in `tests/`.

## Set up

Needs Python 3.10 or newer and about 2 GB of disk. After installing it, choose **Set up** beside it in Settings → Plugins. The computer that runs AgentD Next creates a Python environment with CPU torch, transformers and pypdf (the PDF reader, installed only if it matches its pinned sha256 hash) in the plugin's data folder (`plugins/data/redact` in AgentD Next's data folder), downloads the model and checks it; you can follow its progress there, from any client. It can be turned on once setup has finished. Choose **Set up again** to repair a damaged download. Removing the plugin offers to delete the data folder too.

Without the app, run `python3 <plugin folder>/setup_env.py` on that computer.

## What to know

- Redaction can miss sensitive details. Read the change before you send it.
- A value found anywhere in the message is replaced everywhere in it, in the text and every attachment; for a name, each part of three or more letters is replaced on its own too.
- It covers the messages you send from the composer: the text, UTF-8 text files up to 1 MB, Word documents (`.docx`) and PDFs with a text layer, up to 20 MB each. A message with an image or another kind of file is stopped; remove the file or paste its text. What agents read from your files, tool output and workspace context is not covered.
- A Word document or PDF is sent as its text only, redacted, in a `.txt` file named after it (`lease.docx` goes as `lease.docx.txt`); the file itself is not sent. The agent sees text only: layout, formatting, comments, tracked changes (deleted text is left out, inserted text kept), images and anything else in the file that is not its text are lost. Headers, footers, footnotes and endnotes of a Word document are kept. The review shows the text of each file before it is sent.
- A scanned PDF, or a PDF page made of images, has no text to read: a PDF with no text at all is stopped with a reason that says so, and the image-only pages of a mixed PDF are left out. There is no OCR. A PDF with a password is stopped.
- One message can hold up to 100,000 characters; split longer ones.
- In one conversation a value keeps its placeholder: a name sent again is `[PERSON_1]` again, even if the model does not find it the second time, and a new name gets the next number. The review shows which placeholders are new.
- Replies show the original values in place of the placeholders, highlighted, and copying a reply gives the original values. The agent only ever sees placeholders, and files it writes keep them.
- The plugin writes nothing to disk. AgentD Next keeps each conversation's placeholder map on the computer that runs it, readable by your user account only, and deletes it with the conversation.
