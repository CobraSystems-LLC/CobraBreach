#!/usr/bin/env python3
"""CobraBreach - breach lookup tool.

Check whether passwords or email addresses appear in known data breaches.

Password checks use the HaveIBeenPwned "Pwned Passwords" range API with
k-anonymity: only the first 5 hex characters of the SHA-1 hash ever leave
the machine, so the password (and even its full hash) is never transmitted.
A fully offline mode checks against a local SHA-1 hash list instead.

Email checks use the HIBP v3 breachedaccount API and require an API key
(pass --api-key or set the HIBP_API_KEY environment variable).

Pure standard library; Python 3.10+.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "CobraBreach"
PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACH_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
USER_AGENT = f"{APP_NAME}/1.0 (breach-lookup-cli)"
REQUEST_TIMEOUT = 15
# HIBP asks clients to stay under 1 request per 1.5 seconds.
ONLINE_BATCH_DELAY = 1.6


class BreachLookupError(Exception):
    """Base error for failed lookups."""


@dataclass
class PasswordResult:
    digest: str
    count: int
    source: str  # "hibp-k-anonymity" or "local-db"

    @property
    def breached(self) -> bool:
        return self.count > 0


@dataclass
class EmailBreach:
    name: str
    domain: str
    breach_date: str
    pwn_count: int
    data_classes: list[str] = field(default_factory=list)


def sha1_hex(text: str) -> str:
    """Uppercase hex SHA-1, the format HIBP uses."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def check_password_online(password: str, timeout: int = REQUEST_TIMEOUT) -> PasswordResult:
    """k-anonymity check: only the 5-char hash prefix is sent to HIBP."""
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        PWNED_PASSWORDS_RANGE_URL.format(prefix=prefix),
        # Add-Padding makes response sizes uniform so traffic analysis
        # cannot reveal whether the password was found.
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise BreachLookupError(f"Could not reach the Pwned Passwords API: {exc}") from exc

    count = 0
    for line in body.splitlines():
        hash_suffix, _, hits = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            try:
                count = int(hits.strip())
            except ValueError:
                count = 1
            break
    return PasswordResult(digest=digest, count=count, source="hibp-k-anonymity")


def load_local_db(path: Path) -> dict[str, int]:
    """Load an offline hash list: one SHA-1 per line, optionally 'HASH:COUNT'.

    Compatible with the downloadable HIBP Pwned Passwords corpus
    (SHA-1, ordered by hash) as well as plain hash-per-line lists.
    """
    if not path.is_file():
        raise BreachLookupError(f"Local database not found: {path}")
    database: dict[str, int] = {}
    valid = set("0123456789ABCDEF")
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            hash_part, _, count_part = line.partition(":")
            digest = hash_part.strip().upper()
            if len(digest) != 40 or any(char not in valid for char in digest):
                raise BreachLookupError(f"{path}:{line_number}: not a SHA-1 hash: {line!r}")
            count = 1
            if count_part.strip():
                try:
                    count = int(count_part.strip())
                except ValueError as exc:
                    raise BreachLookupError(
                        f"{path}:{line_number}: bad count in {line!r}"
                    ) from exc
            database[digest] = count
    return database


def check_password_local(password: str, database: dict[str, int]) -> PasswordResult:
    digest = sha1_hex(password)
    return PasswordResult(digest=digest, count=database.get(digest, 0), source="local-db")


def check_email_online(
    email: str, api_key: str, timeout: int = REQUEST_TIMEOUT
) -> list[EmailBreach]:
    """HIBP v3 breachedaccount lookup. Requires a paid HIBP API key."""
    account = urllib.parse.quote(email.strip(), safe="")
    url = HIBP_BREACH_ACCOUNT_URL.format(account=account) + "?truncateResponse=false"
    request = urllib.request.Request(
        url, headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []  # HIBP signals "no breaches" with a 404.
        if exc.code == 401:
            raise BreachLookupError("HIBP rejected the API key (HTTP 401).") from exc
        if exc.code == 429:
            raise BreachLookupError("Rate limited by HIBP — wait a moment and retry.") from exc
        raise BreachLookupError(f"HIBP returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise BreachLookupError(f"Could not reach HIBP: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BreachLookupError("HIBP returned malformed JSON.") from exc

    breaches: list[EmailBreach] = []
    for item in payload if isinstance(payload, list) else []:
        breaches.append(
            EmailBreach(
                name=str(item.get("Name", "")),
                domain=str(item.get("Domain", "")),
                breach_date=str(item.get("BreachDate", "")),
                pwn_count=int(item.get("PwnCount", 0) or 0),
                data_classes=[str(entry) for entry in item.get("DataClasses", [])],
            )
        )
    return breaches


def print_password_result(label: str, result: PasswordResult) -> None:
    if result.breached:
        print(
            f"[PWNED] {label}: seen {result.count:,} time(s) in breaches "
            f"({result.source}). Change it everywhere it is reused."
        )
    else:
        print(f"[OK]    {label}: not found in {result.source} data.")


def print_email_result(email: str, breaches: list[EmailBreach]) -> None:
    if not breaches:
        print(f"[OK]    {email}: no breaches found.")
        return
    print(f"[PWNED] {email}: found in {len(breaches)} breach(es):")
    for breach in sorted(breaches, key=lambda item: item.breach_date, reverse=True):
        classes = ", ".join(breach.data_classes) or "unspecified data"
        print(
            f"  - {breach.name} ({breach.domain}) on {breach.breach_date}: "
            f"{breach.pwn_count:,} accounts, exposed: {classes}"
        )
    print("Action: change the password on every site sharing those credentials "
          "and enable 2FA where possible.")


def write_json_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"JSON report written to {path}")


def cmd_password(args: argparse.Namespace) -> int:
    password = args.password_value
    if password is None:
        password = getpass.getpass("Password to check (input hidden): ")
    if not password:
        print("No password supplied.", file=sys.stderr)
        return 2

    try:
        if args.local_db:
            database = load_local_db(Path(args.local_db))
            result = check_password_local(password, database)
        else:
            result = check_password_online(password)
    except BreachLookupError as exc:
        print(f"Lookup failed: {exc}", file=sys.stderr)
        return 2

    print_password_result("password", result)
    if args.json:
        write_json_report(Path(args.json), {
            "type": "password",
            "breached": result.breached,
            "count": result.count,
            "source": result.source,
        })
    return 1 if result.breached else 0


def cmd_batch(args: argparse.Namespace) -> int:
    password_file = Path(args.file)
    if not password_file.is_file():
        print(f"File not found: {password_file}", file=sys.stderr)
        return 2
    passwords = [
        line.strip()
        for line in password_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    if not passwords:
        print("No passwords found in the file.", file=sys.stderr)
        return 2

    database: dict[str, int] | None = None
    if args.local_db:
        try:
            database = load_local_db(Path(args.local_db))
        except BreachLookupError as exc:
            print(f"Lookup failed: {exc}", file=sys.stderr)
            return 2
    elif not args.yes:
        print(
            f"About to check {len(passwords)} password(s) online "
            f"(~{ONLINE_BATCH_DELAY}s apart for rate limits). Re-run with --yes to proceed."
        )
        return 2

    results: list[tuple[str, PasswordResult]] = []
    breached_count = 0
    for index, password in enumerate(passwords):
        try:
            if database is not None:
                result = check_password_local(password, database)
            else:
                if index:
                    time.sleep(ONLINE_BATCH_DELAY)
                result = check_password_online(password)
        except BreachLookupError as exc:
            print(f"Lookup failed for entry {index + 1}: {exc}", file=sys.stderr)
            continue
        results.append((f"entry {index + 1}", result))
        print_password_result(f"entry {index + 1}", result)
        breached_count += int(result.breached)

    print(f"\nSummary: {breached_count}/{len(passwords)} password(s) breached.")
    if args.json:
        write_json_report(Path(args.json), {
            "type": "batch",
            "checked": len(results),
            "breached": breached_count,
            "entries": [
                {"label": label, "breached": r.breached, "count": r.count, "source": r.source}
                for label, r in results
            ],
        })
    return 1 if breached_count else 0


def cmd_email(args: argparse.Namespace) -> int:
    api_key = args.api_key or os.environ.get("HIBP_API_KEY", "")
    if not api_key:
        print(
            "Email lookups need a HIBP API key. Pass --api-key or set HIBP_API_KEY.",
            file=sys.stderr,
        )
        return 2
    try:
        breaches = check_email_online(args.email, api_key)
    except BreachLookupError as exc:
        print(f"Lookup failed: {exc}", file=sys.stderr)
        return 2

    print_email_result(args.email, breaches)
    if args.json:
        write_json_report(Path(args.json), {
            "type": "email",
            "email": args.email,
            "breached": bool(breaches),
            "breaches": [breach.__dict__ for breach in breaches],
        })
    return 1 if breaches else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description=(
            "Breach lookup tool. Password checks use k-anonymity "
            "(only a 5-char SHA-1 prefix leaves the machine) or a fully "
            "offline local hash database."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    password_parser = subparsers.add_parser(
        "password", help="Check a single password (secure hidden prompt)."
    )
    password_parser.add_argument(
        "--password-value",
        dest="password_value",
        help="Password on the command line (discouraged: visible in shell history).",
    )
    password_parser.add_argument("--local-db", help="Offline SHA-1 hash list instead of the API.")
    password_parser.add_argument("--json", help="Write a JSON report to this path.")
    password_parser.set_defaults(handler=cmd_password)

    batch_parser = subparsers.add_parser(
        "batch", help="Check every password in a file (one per line)."
    )
    batch_parser.add_argument("file", help="File containing one password per line.")
    batch_parser.add_argument("--local-db", help="Offline SHA-1 hash list instead of the API.")
    batch_parser.add_argument("--yes", action="store_true", help="Confirm an online batch run.")
    batch_parser.add_argument("--json", help="Write a JSON report to this path.")
    batch_parser.set_defaults(handler=cmd_batch)

    email_parser = subparsers.add_parser(
        "email", help="Check an email address against HIBP breaches (needs API key)."
    )
    email_parser.add_argument("email", help="Email address to look up.")
    email_parser.add_argument("--api-key", help="HIBP API key (or set HIBP_API_KEY).")
    email_parser.add_argument("--json", help="Write a JSON report to this path.")
    email_parser.set_defaults(handler=cmd_email)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())
