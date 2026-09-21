# CobraBreach

Breach lookup tool: find out whether your passwords or email addresses have appeared in known data breaches — without ever sending the secret itself over the network.

## Features

- **k-anonymity password checks**: uses the HaveIBeenPwned *Pwned Passwords* range API. Only the first 5 hex characters of the SHA-1 hash leave the machine; the full hash is matched locally. `Add-Padding` is requested so response sizes cannot leak whether you were found.
- **Fully offline mode**: check passwords against a local SHA-1 hash list (compatible with the downloadable HIBP Pwned Passwords corpus, `HASH:COUNT` or plain `HASH` per line). Nothing touches the network.
- **Batch checks**: verify a whole file of passwords (one per line), online (rate-limit friendly, ~1.6s between calls) or offline.
- **Email breach lookup**: lists every HIBP breach an address appears in, with dates, affected account counts, and exposed data classes. Requires a HIBP API key.
- **Secure prompts**: passwords are read with hidden input — never echoed, never logged. JSON report export for every mode.
- **Script-friendly exit codes**: `0` = clean, `1` = breached, `2` = error.
- **Pure stdlib**: Python 3.10+, zero third-party dependencies. Works on Windows, Linux and ChromeOS (Crostini).

## Requirements

- Python 3.10+
- Network access for online lookups (offline mode needs only a hash list)
- A HIBP API key for email lookups (get one at <https://haveibeenpwned.com/API/Key>)

## Run

Check a password (hidden prompt, online k-anonymity):

```bash
python3 cobrabreach.py password
```

Check a password completely offline:

```bash
python3 cobrabreach.py password --local-db pwned-passwords-sha1.txt
```

Batch-check a file of passwords:

```bash
python3 cobrabreach.py batch passwords.txt --local-db pwned-passwords-sha1.txt
python3 cobrabreach.py batch passwords.txt --yes            # online, rate-limited
```

Look up an email address:

```bash
python3 cobrabreach.py email alice@example.com --api-key YOUR_KEY
HIBP_API_KEY=YOUR_KEY python3 cobrabreach.py email alice@example.com
```

Export results:

```bash
python3 cobrabreach.py password --json report.json
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Not found in any breach |
| 1 | Found in one or more breaches |
| 2 | Lookup error (network, bad key, bad input) |

## Tests

```bash
python3 -m unittest discover -s tests
```

The test suite uses mocked HTTP responses — no network access or API key needed.

## Privacy notes

- `password` and `batch` never transmit the password or its full hash; only a 5-character SHA-1 prefix is sent when online.
- `email` sends the address to HIBP (that is the point of the lookup) over HTTPS only.
- CobraBreach writes nothing to disk unless you pass `--json`.
