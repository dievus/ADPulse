#!/usr/bin/env python3
"""
AD Security Scanner - Entry Point

Usage examples
──────────────
  # Plaintext password (existing behaviour, unchanged)
  python ADPulse.py --domain corp.local --user admin --password 'P@ssw0rd!'

  # NT hash only (pass-the-hash)
  python ADPulse.py --domain corp.local --user admin --hash 31d6cfe0d16ae931b73c59d7e0c089c0

  # LM:NT hash pair (pass-the-hash)
  python ADPulse.py --domain corp.local --user admin --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

  # With explicit DC and HTML-only report
  python ADPulse.py --domain corp.local --user admin --hash <NT> \
      --dc-ip 10.0.0.1 --report html
"""

import argparse
import datetime
import sys
from pathlib import Path

from connector import ADConnector, resolve_dc, parse_hash
from checks import run_all_checks
from models import ScanResult
from report import print_report, export_json, export_html


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ADPulse — Open-Source Active Directory Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("--domain",     required=True,
                   help="Target AD domain (e.g. corp.local)")
    p.add_argument("--user",       required=True,
                   help="Domain username (SAM account name)")
    p.add_argument("--dc-ip",
                   help="Domain Controller IP (auto-resolved via DNS if omitted)")
    p.add_argument("--report",
                   choices=["console", "json", "html", "all"], default="all",
                   help="Report format(s) to produce (default: all)")
    p.add_argument("--output-dir", default=".",
                   help="Parent directory for the Reports/ folder (default: current dir)")
    p.add_argument("--no-color",   action="store_true",
                   help="Disable ANSI colour output")

    # ── Credential group: password OR hash, exactly one required ──────────────
    creds = p.add_mutually_exclusive_group(required=True)
    creds.add_argument(
        "--password",
        metavar="PASSWORD",
        help="Plaintext domain password",
    )
    creds.add_argument(
        "--hash", "-H",
        metavar="[LMHASH:]NTHASH",
        dest="hash",
        help=(
            "NT hash (or LM:NT pair) for pass-the-hash authentication. "
            "The NT hash is a 32-character hex string, e.g. "
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        ),
    )

    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # ── Colour init ───────────────────────────────────────────────────────────
    try:
        from colorama import init as cinit
        cinit(autoreset=True, strip=args.no_color)
    except ImportError:
        pass

    # ── Banner ────────────────────────────────────────────────────────────────
    print("╔═══════════════════════════════════════════╗")
    print("║ ADPulse Active Directory Security Scanner ║")
    print("║                version 1.0                ║")
    print("║                by TheMayor                ║")
    print("╚═══════════════════════════════════════════╝\n")

    # ── Credential handling ───────────────────────────────────────────────────
    password = ""
    lm_hash  = b""
    nt_hash  = b""

    if args.password:
        password = args.password
        auth_desc = "password"
    else:
        try:
            lm_hash, nt_hash = parse_hash(args.hash)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)
        auth_desc = f"pass-the-hash (NT: {nt_hash.hex()})"

    print(f"[+] Auth mode         : {auth_desc}")

    # ── DC resolution ─────────────────────────────────────────────────────────
    dc_ip = args.dc_ip or resolve_dc(args.domain)
    if not dc_ip:
        print("[!] Could not resolve DC. Use --dc-ip to specify one explicitly.")
        sys.exit(1)
    print(f"[+] Domain Controller : {dc_ip}")

    # ── Connect ───────────────────────────────────────────────────────────────
    ad = ADConnector(
        dc_ip    = dc_ip,
        domain   = args.domain,
        username = args.user,
        password = password,
        lm_hash  = lm_hash,
        nt_hash  = nt_hash,
    )
    if not ad.connect():
        print("[!] Could not establish LDAP connection. Aborting.")
        sys.exit(1)
    print(f"[+] LDAP bind successful\n")

    # ── Run checks ────────────────────────────────────────────────────────────
    findings, stats = run_all_checks(ad)

    # ── Build result ──────────────────────────────────────────────────────────
    result = ScanResult(
        domain    = args.domain,
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        dc_ip     = dc_ip,
        findings  = findings,
        stats     = stats,
    )

    # ── Output ────────────────────────────────────────────────────────────────
    out = Path(args.output_dir) / "Reports"
    out.mkdir(parents=True, exist_ok=True)
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dn  = args.domain

    if args.report in ("console", "all"):
        print_report(result)
    if args.report in ("json", "all"):
        export_json(result, str(out / f"ad_scan_{dn}_{ts}.json"))
    if args.report in ("html", "all"):
        export_html(result, str(out / f"ad_scan_{dn}_{ts}.html"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user (Ctrl+C). Exiting.")
        sys.exit(130)
