"""Check whether an email address can actually receive mail.

Most checkers stop at the format of the address. This one asks the receiving
mail server directly, and reports "unknown" when the server refuses to say.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import secrets
import smtplib
import socket
import sys
from dataclasses import asdict, dataclass

import dns.resolver

__version__ = "0.1.0"

VALID = "valid"
INVALID = "invalid"
RISKY = "risky"
UNKNOWN = "unknown"

# RFC 5321 caps the local part at 64 characters and the whole address at 254.
MAX_LOCAL = 64
MAX_TOTAL = 254

_SYNTAX = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)

# A 2xx reply to RCPT TO means the server accepted the recipient.
ACCEPTED = frozenset({250, 251})

# Mailboxes that usually belong to a team rather than a person. Still real
# addresses, so this is reported as a flag and does not change the status.
ROLE_NAMES = frozenset(
    """admin administrator abuse alerts billing careers contact donotreply
    do-not-reply enquiries feedback help hello hostmaster hr info inquiries
    jobs legal mailer-daemon marketing media newsletter no-reply noreply
    notifications office postmaster press root sales security service
    subscribe support team unsubscribe webmaster""".split()
)

# Starter list of throwaway mail services. Deliberately short: a handful of
# providers cover most real traffic. See README for the full public list.
DISPOSABLE_DOMAINS = frozenset(
    """10minutemail.com 1secmail.com 20minutemail.com 33mail.com
    dispostable.com discard.email emailondeck.com fakeinbox.com getairmail.com
    getnada.com grr.la guerrillamail.com guerrillamailblock.com inboxkitten.com
    mailcatch.com maildrop.cc mailinator.com mailnesia.com mailsac.com
    minuteinbox.com mohmal.com moakt.com mytemp.email sharklasers.com
    spam4.me spamgourmet.com tempail.com tempinbox.com tempmail.com
    tempmailo.com temp-mail.org tempr.email throwawaymail.com trashmail.com
    yopmail.com""".split()
)


@dataclass
class Result:
    email: str
    status: str
    reason: str
    mx: str | None = None
    catch_all: bool | None = None
    disposable: bool = False
    role: bool = False


def find_mx(domain: str, timeout: float = 10.0) -> tuple[str | None, str]:
    """Return the best mail host for a domain, and a note explaining the lookup.

    Falls back to the A record when there is no MX record, which RFC 5321
    allows and plenty of small domains rely on.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        records = resolver.resolve(domain, "MX")
        best = min(records, key=lambda r: r.preference)
        return str(best.exchange).rstrip("."), "mx record found"
    except dns.resolver.NXDOMAIN:
        return None, "domain does not exist"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return None, "dns lookup timed out"
    except dns.exception.DNSException:
        return None, "dns lookup failed"

    try:
        resolver.resolve(domain, "A")
        return domain, "no mx record, using the domain itself"
    except dns.exception.DNSException:
        return None, "domain has no mail server"


def probe(
    mx_host: str,
    email: str,
    domain: str,
    from_address: str,
    timeout: float = 10.0,
) -> tuple[int, bool | None]:
    """Ask the mail server about an address without sending anything.

    Returns the reply code for the address, plus whether the domain accepts
    every address it is offered. That second answer is the important one: a
    domain that accepts everything cannot confirm any single mailbox.
    """
    with smtplib.SMTP(timeout=timeout) as smtp:
        smtp.connect(mx_host, 25)
        smtp.ehlo_or_helo_if_needed()
        smtp.mail(from_address)

        code, _ = smtp.rcpt(email)

        try:
            decoy = f"{secrets.token_hex(12)}@{domain}"
            decoy_code, _ = smtp.rcpt(decoy)
            catch_all = decoy_code in ACCEPTED
        except (smtplib.SMTPException, OSError):
            # Some servers hang up after the first recipient. Without the
            # second answer we cannot rule out a catch-all.
            catch_all = None

    return code, catch_all


def decide(code: int, catch_all: bool | None, disposable: bool) -> tuple[str, str]:
    """Turn a server reply into a status and a plain explanation.

    Kept free of network calls so the rules can be tested directly.
    """
    if code in ACCEPTED:
        if catch_all is True:
            return RISKY, "server accepts every address on this domain, so this mailbox cannot be confirmed"
        if catch_all is None:
            return UNKNOWN, "server accepted the address but closed before the catch-all check"
        if disposable:
            return RISKY, "mailbox exists but the domain is a throwaway mail service"
        return VALID, "server confirmed the mailbox exists"

    if 500 <= code < 600:
        return INVALID, f"server rejected the address (code {code})"

    if 400 <= code < 500:
        return UNKNOWN, f"server asked us to try again later (code {code})"

    # smtplib reports -1 when the connection drops or the reply cannot be read.
    # Servers that dislike being probed often behave this way.
    if code < 200:
        return UNKNOWN, "server closed the connection without answering"

    return UNKNOWN, f"unexpected reply from server (code {code})"


def verify(
    email: str,
    from_address: str = "verify@example.com",
    timeout: float = 10.0,
) -> Result:
    """Check one address end to end."""
    email = email.strip()

    if len(email) > MAX_TOTAL or not _SYNTAX.match(email):
        return Result(email, INVALID, "not a valid email address format")

    local, _, domain = email.rpartition("@")
    domain = domain.lower()

    if len(local) > MAX_LOCAL:
        return Result(email, INVALID, "the part before the @ is too long")

    disposable = domain in DISPOSABLE_DOMAINS
    role = local.lower() in ROLE_NAMES

    mx_host, note = find_mx(domain, timeout=timeout)
    if mx_host is None:
        return Result(email, INVALID, note, disposable=disposable, role=role)

    try:
        code, catch_all = probe(mx_host, email, domain, from_address, timeout)
    except (socket.timeout, TimeoutError):
        return Result(
            email, UNKNOWN, "mail server did not respond in time",
            mx=mx_host, disposable=disposable, role=role,
        )
    except (smtplib.SMTPException, OSError) as exc:
        return Result(
            email, UNKNOWN,
            f"could not reach the mail server ({type(exc).__name__}), "
            "outbound port 25 may be blocked on this network",
            mx=mx_host, disposable=disposable, role=role,
        )

    status, reason = decide(code, catch_all, disposable)
    return Result(email, status, reason, mx_host, catch_all, disposable, role)


def verify_many(
    emails: list[str],
    from_address: str = "verify@example.com",
    timeout: float = 10.0,
    workers: int = 5,
) -> list[Result]:
    """Check several addresses at once, keeping the input order."""
    if not emails:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda e: verify(e, from_address, timeout), emails))


def _split(values: list[str]) -> list[str]:
    out = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mailprobe",
        description="Check whether an email address can actually receive mail.",
    )
    parser.add_argument("emails", nargs="*", help="one or more addresses, separated by commas or spaces")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "--from-address",
        default="verify@example.com",
        help="address to introduce ourselves with, use a domain you own",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait per step")
    parser.add_argument("--workers", type=int, default=5, help="how many addresses to check at once")
    args = parser.parse_args(argv)

    emails = _split(args.emails) if args.emails else _split(sys.stdin.read().splitlines())
    if not emails:
        parser.error("no addresses given")

    results = verify_many(emails, args.from_address, args.timeout, args.workers)

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        width = max(len(r.email) for r in results)
        for r in results:
            flags = "".join(f" [{f}]" for f in ("disposable", "role") if getattr(r, f))
            print(f"{r.email:<{width}}  {r.status:<7}  {r.reason}{flags}")

    return 1 if any(r.status == INVALID for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
