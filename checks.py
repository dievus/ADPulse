"""
All security checks. Each function receives an ADConnector and returns
(list[Finding], dict).  run_all_checks() aggregates them all.

Original checks : 1–24 (preserved verbatim)
New checks      : 25–35
  25. GPP / cpassword in SYSVOL (MS14-025)
  26. AdminSDHolder ACL Inspection
  27. SID History Abuse
  28. Shadow Credentials (msDS-KeyCredentialLink)
  29. RC4 / Legacy Kerberos Encryption Still Permitted
  30. Foreign Security Principals in Privileged Groups
  31. Pre-Windows 2000 Compatible Access Group
  32. Dangerous Constrained Delegation Targets (LDAP / CIFS / HOST on DCs)
  33. Orphaned AD Subnets (not mapped to any site)
  34. Legacy FRS SYSVOL Replication
  35. RBCD Configured on the Domain Object Itself
  Bonus: Indirect Privileged Group Membership (non-direct transitive members)
"""

import datetime
import os
import socket
import struct
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Any
from connector import ADConnector
from models import Finding

F = Finding
NOW = datetime.datetime.now(datetime.timezone.utc)


# ── helpers ────────────────────────────────────────────────────────────────────


def _attr_raw(entry, name):
    raw = getattr(entry, name, None)
    if raw is None:
        return None
    if hasattr(raw, "value"):
        return raw.value
    if hasattr(raw, "raw_values") and raw.raw_values:
        return raw.raw_values[0]
    return raw


def _ldap_ts_to_dt(raw):
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        return raw.replace(tzinfo=datetime.timezone.utc) if raw.tzinfo is None else raw
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str) and len(raw) >= 14 and not raw.lstrip("-").isdigit():
        try:
            clean = raw.split(".")[0].replace("Z", "")
            return datetime.datetime.strptime(clean, "%Y%m%d%H%M%S").replace(
                tzinfo=datetime.timezone.utc
            )
        except (ValueError, IndexError):
            pass
    try:
        v = int(raw)
        if v <= 0:
            return None
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch + datetime.timedelta(microseconds=v // 10)
    except (ValueError, TypeError, OverflowError):
        return None


def _days_since(dt):
    if dt is None:
        return None
    return (NOW - dt).days


def _100ns_to_days(val: int) -> int:
    if val >= 0:
        return 0
    return abs(val) // 864_000_000_000


# UAC flags
UAC_DISABLED = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_NO_PREAUTH = 0x400000
UAC_USE_DES_KEY_ONLY = 0x200000

# Well-known SID RIDs
_DA_RID = "512"
_EA_RID = "519"
_DC_RID = "516"
_RODC_RID = "521"
_EDC_RID = "498"
_SA_RID = "518"

_ADMINS = "S-1-5-32-544"
_EVERYONE = "S-1-1-0"
_AUTH_USERS = "S-1-5-11"
_ANON = "S-1-5-7"
_ENTERPRISE_DCS = "S-1-5-9"
_SYSTEM = "S-1-5-18"

# Access mask flags
AM_GENERIC_ALL = 0x10000000
AM_GENERIC_WRITE = 0x40000000
AM_WRITE_DACL = 0x00040000
AM_WRITE_OWNER = 0x00080000
AM_WRITE_PROP = 0x00000020

# Replication right GUIDs
REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
REPL_GET_CHANGES_FIL = "89e95b76-444d-4c62-991a-0facbeda640c"

# ADCS EKU OIDs
CLIENT_AUTH = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.2.3.4",
    "1.3.6.1.4.1.311.20.2.2",
    "2.5.29.37.0",
}
ANY_PURPOSE = "2.5.29.37.0"
ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"

ENROLL_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

CA_MANAGE = 0x00000001
CA_OFFICER = 0x00000010

_CA_TYPE_TEMPLATES = {"CA", "SubCA", "CrossCA", "RootCertificateAuthority"}

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x00000400
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x00000800
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x00000008
CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x00000010
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x00000004
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_AUTO_ENROLLMENT = 0x00000020

DEPRECATED_OS_PATTERNS = (
    "windows xp",
    "windows vista",
    "windows 7",
    "windows 8",
    "windows 8.1",
    "nt 4",
    "windows 2000",
    "server 2003",
    "server 2008",
)

# High-value Kerberos service prefixes for delegation checks (check 32)
DANGEROUS_SVC_PREFIXES = (
    "ldap/",
    "ldaps/",
    "krbtgt/",
    "host/",
    "cifs/",
    "gc/",
    "rpcss/",
    "dnshost/",
)


def _priv_group_dns(base_dn: str) -> set:
    return {
        f"CN=Domain Admins,CN=Users,{base_dn}",
        f"CN=Enterprise Admins,CN=Users,{base_dn}",
        f"CN=Schema Admins,CN=Users,{base_dn}",
        f"CN=Administrators,CN=Builtin,{base_dn}",
        f"CN=Account Operators,CN=Builtin,{base_dn}",
        f"CN=Backup Operators,CN=Builtin,{base_dn}",
        f"CN=Print Operators,CN=Builtin,{base_dn}",
        f"CN=Server Operators,CN=Builtin,{base_dn}",
        f"CN=Group Policy Creator Owners,CN=Users,{base_dn}",
        f"CN=Replicator,CN=Builtin,{base_dn}",
    }


def _get_domain_sid(ad: ADConnector) -> str:
    dom = ad.get_domain_object()
    if not dom:
        return ""
    raw = getattr(dom, "objectSid", None)
    if not raw or not raw.value:
        return ""
    s = str(raw.value)
    parts = s.split("-")
    if len(parts) == 8:
        return "-".join(parts[:7])
    return s


def _sid_is_privileged(sid: str, domain_sid: str) -> bool:
    always_ok = {
        _ADMINS,
        _ENTERPRISE_DCS,
        _SYSTEM,
        "S-1-5-9",
        "S-1-5-32-548",
        "S-1-5-32-569",
        "S-1-5-11",
    }
    if sid in always_ok:
        return True
    if not domain_sid:
        return False
    for rid in (_DA_RID, _EA_RID, _DC_RID, _SA_RID, _RODC_RID, _EDC_RID, "517"):
        if sid == f"{domain_sid}-{rid}":
            return True
    return False


def _sid_is_dc(sid: str, ad: ADConnector) -> bool:
    try:
        results = ad.search(
            f"(&(objectClass=computer)(objectSid={sid})"
            f"(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName"],
        )
        return bool(results)
    except Exception:
        return False


# ── ACL binary parsing ──────────────────────────────────────────────────────────


def _parse_sd(raw_sd: bytes):
    import struct

    aces = []
    if not raw_sd or len(raw_sd) < 20:
        return aces
    try:
        revision, sbz1, control, off_owner, off_group, off_sacl, off_dacl = (
            struct.unpack_from("<BBHIIII", raw_sd, 0)
        )
        if off_dacl == 0:
            return aces
        acl_rev, _, acl_size, ace_count, _ = struct.unpack_from(
            "<BBHHH", raw_sd, off_dacl
        )
        offset = off_dacl + 8
        for _ in range(ace_count):
            if offset + 4 > len(raw_sd):
                break
            ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", raw_sd, offset)
            ace_data = raw_sd[offset : offset + ace_size]
            access_mask = (
                struct.unpack_from("<I", ace_data, 4)[0] if len(ace_data) >= 8 else 0
            )
            object_type = None
            sid_offset = 8
            if ace_type in (0x05, 0x06, 0x07, 0x08):
                obj_flags = (
                    struct.unpack_from("<I", ace_data, 8)[0]
                    if len(ace_data) >= 12
                    else 0
                )
                sid_offset = 12
                if obj_flags & 0x1:
                    if len(ace_data) >= sid_offset + 16:
                        b = ace_data[sid_offset : sid_offset + 16]
                        object_type = (
                            f"{int.from_bytes(b[0:4],'little'):08x}-"
                            f"{int.from_bytes(b[4:6],'little'):04x}-"
                            f"{int.from_bytes(b[6:8],'little'):04x}-"
                            f"{b[8:10].hex()}-{b[10:16].hex()}"
                        )
                        sid_offset += 16
                    if obj_flags & 0x2:
                        sid_offset += 16
            if sid_offset + 8 <= len(ace_data):
                sid_rev = ace_data[sid_offset]
                sub_count = ace_data[sid_offset + 1]
                authority = int.from_bytes(
                    ace_data[sid_offset + 2 : sid_offset + 8], "big"
                )
                subs = []
                for i in range(sub_count):
                    so = sid_offset + 8 + i * 4
                    if so + 4 <= len(ace_data):
                        subs.append(struct.unpack_from("<I", ace_data, so)[0])
                sid = f"S-{sid_rev}-{authority}-" + "-".join(str(s) for s in subs)
                aces.append(
                    {
                        "ace_type": ace_type,
                        "access_mask": access_mask,
                        "object_type": object_type,
                        "trustee_sid": sid,
                    }
                )
            offset += ace_size
    except Exception:
        pass
    return aces


def _get_template_enrollees(ad: ADConnector, tmpl_dn: str, domain_sid: str) -> list:
    from ldap3 import BASE
    from ldap3.protocol.microsoft import security_descriptor_control

    enrollees = []
    try:
        ctrl = security_descriptor_control(sdflags=0x04)
        ad.conn.search(
            search_base=tmpl_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["nTSecurityDescriptor"],
            controls=ctrl,
        )
        if not ad.conn.entries:
            return enrollees
        sd_attr = getattr(ad.conn.entries[0], "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            return enrollees
        seen = set()
        for ace in _parse_sd(raw_sd):
            if ace["ace_type"] not in (0x00, 0x05):
                continue
            sid = ace["trustee_sid"]
            otype = (ace.get("object_type") or "").lower().strip()
            mask = ace["access_mask"]
            if ace["ace_type"] == 0x05 and otype not in (
                ENROLL_RIGHT,
                AUTOENROLL_RIGHT,
            ):
                continue
            if ace["ace_type"] == 0x00 and not (mask & AM_GENERIC_ALL):
                continue
            if _sid_is_privileged(sid, domain_sid):
                continue
            if sid in seen:
                continue
            seen.add(sid)
            enrollees.append(ad.resolve_sid(sid))
    except Exception as e:
        print(f"  [~] Enrollee ACL fetch failed ({tmpl_dn[:60]}): {e}")
    return enrollees


def _fmt_tmpl(name: str, enrollees: list) -> str:
    if enrollees:
        return f"{name} (enrollees: {', '.join(enrollees)})"
    return name


# ── SMB probes ─────────────────────────────────────────────────────────────────

_SMB2_DIALECT_MAP = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

_SMB1_NEGOTIATE_PKT = (
    b"\x00\x00\x00\x2f"
    b"\xff\x53\x4d\x42"  # \xffSMB
    b"\x72"  # Command: Negotiate
    b"\x00\x00\x00\x00"  # NT Status
    b"\x18\x01\x28"  # Flags / Flags2
    b"\x00\x00"  # PID High
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Security signature
    b"\x00\x00\xff\xff\xfe\xff\x00\x00\x00\x00"  # Reserved/TID/PID/UID/MID
    b"\x00"  # Word count
    b"\x0c\x00"  # Byte count
    b"\x02NT LM 0.12\x00"  # Dialect
)


def _smb_recv(sock: socket.socket, length: int) -> bytes:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _is_conn_reset(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "10054" in msg
        or "connection was forcibly closed" in msg
        or "connection reset" in msg
        or "econnreset" in msg
    )


def _smb1_negotiate(ip: str, timeout: float = 3.0) -> bool:
    """Return True only if the server responds with a successful SMBv1 negotiate."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 445))
            s.sendall(_SMB1_NEGOTIATE_PKT)
            nb = _smb_recv(s, 4)
            if len(nb) < 4:
                return False
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 256))
            if len(body) < 9:
                return False
            # \xffSMB + 0x72 (negotiate response) + NT Status 0x00000000
            return (
                body[0:4] == b"\xff\x53\x4d\x42"
                and body[4] == 0x72
                and struct.unpack_from("<I", body, 5)[0] == 0
            )
    except Exception:
        return False


def _build_smb2_negotiate() -> bytes:
    """
    Build an SMB2 Negotiate Request offering dialects 2.0.2 – 3.1.1.

    SMB 3.1.1 requires PREAUTH_INTEGRITY_CAPABILITIES (MS-SMB2 §2.2.3).

    Response offsets (from byte 0 of TCP payload, after NetBIOS header):
      0– 3  ProtocolId (\xfeSMB)
      4– 5  StructureSize = 64
      6– 7  CreditCharge
      8–11  NT Status
     12–13  Command
      ...
     64–65  [body] StructureSize = 65
     66–67  [body] SecurityMode     bit 0x01 = enabled, 0x02 = required
     68–69  [body] DialectRevision
    """
    dialects = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)

    # PREAUTH_INTEGRITY_CAPABILITIES context (SHA-512, type 0x0001)
    preauth_data = struct.pack("<HHH", 1, 0, 0x0001)  # 6 bytes
    neg_ctx = (
        struct.pack("<HHI", 0x0001, len(preauth_data), 0) + preauth_data
    )  # 14 bytes total

    # NegotiateContextOffset is absolute from start of SMB2 header (64 bytes).
    # Fixed body = 36, dialects = 10 → absolute 110; pad to 8-byte boundary → 112.
    dialects_end = 64 + 36 + len(dialect_bytes)  # 110
    pad_len = (8 - dialects_end % 8) % 8  # 2
    neg_ctx_offset = dialects_end + pad_len  # 112

    body = (
        struct.pack("<H", 36)  # StructureSize
        + struct.pack("<H", len(dialects))  # DialectCount
        + struct.pack("<H", 0x0001)  # SecurityMode: signing enabled
        + struct.pack("<H", 0)  # Reserved
        + struct.pack("<I", 0x0000007F)  # Capabilities
        + b"\x00" * 16  # ClientGuid
        + struct.pack("<I", neg_ctx_offset)  # NegotiateContextOffset
        + struct.pack("<H", 1)  # NegotiateContextCount
        + struct.pack("<H", 0)  # Reserved2
        + dialect_bytes
        + b"\x00" * pad_len  # Alignment padding
        + neg_ctx
    )

    smb2_hdr = (
        b"\xfeSMB"
        + struct.pack("<H", 64)  # StructureSize
        + b"\x00\x00"  # CreditCharge
        + b"\x00\x00\x00\x00"  # Status
        + b"\x00\x00"  # Command: Negotiate (0)
        + b"\x1f\x00"  # CreditRequest
        + b"\x00\x00\x00\x00"  # Flags
        + b"\x00\x00\x00\x00"  # NextCommand
        + b"\x00" * 8  # MessageId
        + b"\x00" * 4  # Reserved
        + b"\x00" * 4  # TreeId
        + b"\x00" * 8  # SessionId
        + b"\x00" * 16  # Signature
    )

    payload = smb2_hdr + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _check_smb_signing(ip: str, timeout: float = 3.0) -> tuple:
    """
    Return (signing_status, smb_version).

    signing_status : "required" | "enabled_not_required" | "disabled" |
                     "smb2_disabled" | "unreachable" | "error"
    smb_version    : e.g. "SMB 3.1.1", or None
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 445))
            s.sendall(_build_smb2_negotiate())

            nb = _smb_recv(s, 4)
            if len(nb) < 4:
                return "smb2_disabled", None
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 512))

            if len(body) < 68 or body[0:4] != b"\xfeSMB":
                return "smb2_disabled", None

            nt_status = struct.unpack_from("<I", body, 8)[0]
            if nt_status != 0:
                return "error", None

            sec_mode = struct.unpack_from("<H", body, 66)[0]
            dialect_code = (
                struct.unpack_from("<H", body, 68)[0] if len(body) >= 70 else None
            )
            ver = (
                _SMB2_DIALECT_MAP.get(dialect_code)
                if dialect_code is not None
                else None
            )

            if sec_mode & 0x02:
                return "required", ver
            if sec_mode & 0x01:
                return "enabled_not_required", ver
            return "disabled", ver

    except socket.timeout:
        return "error", None
    except ConnectionRefusedError:
        return "unreachable", None
    except Exception as e:
        if _is_conn_reset(e):
            return "smb2_disabled", None
        return "error", None


def _check_null_session(ip: str, timeout: float = 3.0) -> bool:
    null_session_pkt = (
        b"\x00\x00\x00\x59"
        b"\xff\x53\x4d\x42"
        b"\x73"
        b"\x00\x00\x00\x00"
        b"\x18"
        b"\x07\xc0"
        b"\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\xff\xff"
        b"\xff\xfe"
        b"\x00\x00"
        b"\x40\x00"
        b"\x0d"
        b"\xff"
        b"\x00"
        b"\x00\x00"
        b"\xff\x00"
        b"\x02\x00"
        b"\x01\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x60\x48\x06\x06"
        b"\x11\x00"
        b"\x00"
        b"\x00"
        b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
        b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 445))
            s.sendall(null_session_pkt)
            resp = s.recv(256)
            if len(resp) >= 13 and resp[4:8] == b"\xff\x53\x4d\x42":
                return struct.unpack_from("<I", resp, 9)[0] == 0
    except Exception:
        pass
    return False


def _check_smb1_hosts(ad: ADConnector) -> tuple:
    targets = {
        ad.dc_ip: ad.dc_ip
    }  # DC only — domain-wide host scan removed for performance

    print(f"    Probing DC ({ad.dc_ip}) for SMBv1 / signing / null sessions...")
    smb1_vuln, signing_issues, null_sessions = [], [], []

    for label, host in targets.items():
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            continue

        has_smb1 = _smb1_negotiate(ip)
        sign, ver = _check_smb_signing(ip)
        ver_str = ver if ver else "SMB2/3"

        if has_smb1:
            smb1_vuln.append(label)

        if sign == "disabled":
            signing_issues.append(f"{label} ({ver_str}, signing disabled)")
        elif sign == "enabled_not_required":
            signing_issues.append(
                f"{label} ({ver_str}, signing enabled but not required)"
            )
        elif sign == "smb2_disabled" and has_smb1:
            signing_issues.append(
                f"{label} (SMBv1 only — SMB2/3 signing cannot be verified)"
            )
        # "unreachable" / "error" → probe inconclusive, not a misconfiguration

        if _check_null_session(ip):
            null_sessions.append(label)

    return smb1_vuln, signing_issues, null_sessions


# ══════════════════════════════════════════════════════════════════════════════
# ORIGINAL CHECKS 1–24
# ══════════════════════════════════════════════════════════════════════════════

# -- 1. Password Policy --------------------------------------------------------


def check_password_policy(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Password Policy")
    dom = ad.get_domain_object()
    if not dom:
        return findings, stats
    min_len = ad.attr_int(dom, "minPwdLength")
    history = ad.attr_int(dom, "pwdHistoryLength")
    lockout = ad.attr_int(dom, "lockoutThreshold")
    lock_dur = ad.attr_int(dom, "lockoutDuration")
    max_age = _100ns_to_days(ad.attr_int(dom, "maxPwdAge", -1))
    min_age = _100ns_to_days(ad.attr_int(dom, "minPwdAge", 0))
    pwd_props = ad.attr_int(dom, "pwdProperties")
    stats["password_policy"] = dict(
        min_length=min_len,
        history=history,
        lockout_threshold=lockout,
        max_age_days=max_age,
        min_age_days=min_age,
    )
    if min_len < 8:
        findings.append(
            F(
                "Password Policy",
                "Minimum Password Length < 8",
                "HIGH",
                f"Minimum length is {min_len}.",
                recommendation="Set minimum password length to >= 14.",
                risk_score=15,
            )
        )
    elif min_len < 12:
        findings.append(
            F(
                "Password Policy",
                "Minimum Password Length < 12",
                "MEDIUM",
                f"Minimum length is {min_len}.",
                recommendation="Consider raising to 14+ characters.",
                risk_score=5,
            )
        )
    if history < 10:
        findings.append(
            F(
                "Password Policy",
                "Password History Too Short",
                "MEDIUM",
                f"History is {history} (recommended >= 24).",
                recommendation="Set password history to 24.",
                risk_score=5,
            )
        )
    if max_age == 0:
        findings.append(
            F(
                "Password Policy",
                "Passwords Never Expire",
                "MEDIUM",
                "No maximum password age configured.",
                recommendation="Set max password age to <= 90 days.",
                risk_score=10,
            )
        )
    elif max_age > 365:
        findings.append(
            F(
                "Password Policy",
                "Password Max Age > 1 Year",
                "LOW",
                f"Max password age is {max_age} days.",
                recommendation="Reduce to <= 90 days.",
                risk_score=5,
            )
        )
    if lockout == 0:
        findings.append(
            F(
                "Password Policy",
                "No Account Lockout Policy",
                "CRITICAL",
                "Lockout threshold is 0 -- unlimited password guessing allowed.",
                recommendation="Set lockout threshold to 5-10 attempts.",
                risk_score=20,
            )
        )
    elif lockout > 10:
        findings.append(
            F(
                "Password Policy",
                "Lockout Threshold Too High",
                "LOW",
                f"Lockout threshold is {lockout}.",
                recommendation="Reduce to <= 10 failed attempts.",
                risk_score=3,
            )
        )
    if lockout > 0 and lock_dur == 0:
        findings.append(
            F(
                "Password Policy",
                "Lockout Requires Manual Admin Unlock",
                "INFO",
                "Lockout duration is 0 -- admin must manually unlock accounts.",
                recommendation="Set lockout duration to 15-30 minutes unless intentional.",
                risk_score=0,
            )
        )
    if not (pwd_props & 1):
        findings.append(
            F(
                "Password Policy",
                "Password Complexity Disabled",
                "MEDIUM",
                "Complexity requirements are off.",
                recommendation="Enable password complexity or enforce passphrase policy.",
                risk_score=10,
            )
        )
    if pwd_props & 16:
        findings.append(
            F(
                "Password Policy",
                "Reversible Encryption Enabled (Domain Policy)",
                "CRITICAL",
                "Passwords stored with reversible encryption (effectively plaintext).",
                recommendation="Disable reversible password encryption immediately.",
                risk_score=25,
            )
        )
    if min_age == 0:
        findings.append(
            F(
                "Password Policy",
                "No Minimum Password Age",
                "LOW",
                "Users can change passwords immediately, bypassing history controls.",
                recommendation="Set minimum password age to 1 day.",
                risk_score=3,
            )
        )
    psos = ad.search(
        "(objectClass=msDS-PasswordSettings)",
        ["cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold"],
        base=f"CN=Password Settings Container,CN=System,{ad.base_dn}",
    )
    if psos:
        pso_issues = []
        for p in psos:
            pname = ad.attr_str(p, "cn")
            plen = ad.attr_int(p, "msDS-MinimumPasswordLength")
            plockout = ad.attr_int(p, "msDS-LockoutThreshold")
            if plen < 8 or plockout == 0:
                pso_issues.append(f"{pname} (len={plen}, lockout={plockout})")
        if pso_issues:
            findings.append(
                F(
                    "Password Policy",
                    "Weak Fine-Grained Password Policy (PSO)",
                    "HIGH",
                    f"{len(pso_issues)} PSO(s) have weak settings.",
                    details=pso_issues,
                    recommendation="Review and harden all PSOs.",
                    risk_score=10,
                )
            )
        stats["psos"] = [ad.attr_str(p, "cn") for p in psos]
    return findings, stats


# -- 2. Privileged Accounts ----------------------------------------------------


def check_privileged_accounts(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Privileged Accounts")
    PRIV_GROUPS = {
        "Domain Admins": f"CN=Domain Admins,CN=Users,{ad.base_dn}",
        "Enterprise Admins": f"CN=Enterprise Admins,CN=Users,{ad.base_dn}",
        "Schema Admins": f"CN=Schema Admins,CN=Users,{ad.base_dn}",
        "Administrators": f"CN=Administrators,CN=Builtin,{ad.base_dn}",
        "Account Operators": f"CN=Account Operators,CN=Builtin,{ad.base_dn}",
        "Backup Operators": f"CN=Backup Operators,CN=Builtin,{ad.base_dn}",
        "Print Operators": f"CN=Print Operators,CN=Builtin,{ad.base_dn}",
        "Server Operators": f"CN=Server Operators,CN=Builtin,{ad.base_dn}",
        "Group Policy Creator Owners": f"CN=Group Policy Creator Owners,CN=Users,{ad.base_dn}",
        "DNS Admins": f"CN=DnsAdmins,CN=Users,{ad.base_dn}",
        "Remote Desktop Users": f"CN=Remote Desktop Users,CN=Builtin,{ad.base_dn}",
    }
    SENSITIVE = {
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
    }
    for gname, gdn in PRIV_GROUPS.items():
        members = ad.search(
            f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={gdn}))",
            [
                "sAMAccountName",
                "userAccountControl",
                "lastLogonTimestamp",
                "pwdLastSet",
                "description",
            ],
        )
        names, stale, no_expire, pwd_in_desc = [], [], [], []
        for u in members:
            n = ad.attr_str(u, "sAMAccountName")
            names.append(n)
            uac = ad.attr_int(u, "userAccountControl")
            llt = _ldap_ts_to_dt(_attr_raw(u, "lastLogonTimestamp"))
            if _days_since(llt) and _days_since(llt) > 90:
                stale.append(f"{n} ({_days_since(llt)}d inactive)")
            if uac & UAC_DONT_EXPIRE_PASSWD:
                no_expire.append(n)
            desc = ad.attr_str(u, "description").lower()
            for kw in ("password", "passwd", "pwd", "pass=", "mot de passe"):
                if kw in desc:
                    pwd_in_desc.append(n)
                    break
        stats[f"group_{gname}"] = names
        if gname in SENSITIVE and len(names) > 5:
            findings.append(
                F(
                    "Privileged Accounts",
                    f"Too Many Members in '{gname}'",
                    "HIGH",
                    f"{len(names)} members (recommended <= 5).",
                    details=names,
                    recommendation=f"Reduce '{gname}' membership to essential accounts only.",
                    risk_score=15,
                )
            )
        if stale and gname in SENSITIVE:
            findings.append(
                F(
                    "Privileged Accounts",
                    f"Stale Members in '{gname}'",
                    "HIGH",
                    f"{len(stale)} member(s) inactive for 90+ days.",
                    details=stale,
                    recommendation="Disable or remove stale privileged accounts.",
                    risk_score=12,
                )
            )
        if no_expire and gname in SENSITIVE:
            findings.append(
                F(
                    "Privileged Accounts",
                    f"Non-Expiring Passwords in '{gname}'",
                    "MEDIUM",
                    f"{len(no_expire)} admin(s) with non-expiring passwords.",
                    details=no_expire,
                    recommendation="Enforce password expiration on all admin accounts.",
                    risk_score=8,
                )
            )
        if pwd_in_desc:
            findings.append(
                F(
                    "Privileged Accounts",
                    "Password Stored in Account Description",
                    "HIGH",
                    f"{len(pwd_in_desc)} account(s) may have passwords in the Description field.",
                    details=pwd_in_desc,
                    recommendation="Remove credentials from description fields.",
                    risk_score=15,
                )
            )
    admin500 = ad.search(
        "(&(objectClass=user)(adminCount=1))",
        ["sAMAccountName", "userAccountControl", "lastLogonTimestamp"],
    )
    for u in admin500:
        if ad.attr_str(u, "sAMAccountName").lower() in (
            "administrator",
            "administrateur",
        ):
            uac = ad.attr_int(u, "userAccountControl")
            if not (uac & UAC_DISABLED):
                findings.append(
                    F(
                        "Privileged Accounts",
                        "Built-in Administrator Account Enabled",
                        "MEDIUM",
                        "The built-in Administrator account (RID-500) is active.",
                        recommendation="Rename and/or create a decoy Administrator account. Consider disabling it.",
                        risk_score=8,
                    )
                )
            llt = _ldap_ts_to_dt(_attr_raw(u, "lastLogonTimestamp"))
            if llt and _days_since(llt) < 30:
                findings.append(
                    F(
                        "Privileged Accounts",
                        "Built-in Administrator Recently Used",
                        "HIGH",
                        "RID-500 administrator logged in recently -- should not be used for daily tasks.",
                        recommendation="Use named admin accounts; reserve RID-500 for break-glass only.",
                        risk_score=12,
                    )
                )
    krb = ad.search("(&(objectClass=user)(sAMAccountName=krbtgt))", ["pwdLastSet"])
    if krb:
        pls = _ldap_ts_to_dt(_attr_raw(krb[0], "pwdLastSet"))
        days = _days_since(pls)
        if days is None or days > 180:
            findings.append(
                F(
                    "Privileged Accounts",
                    "krbtgt Password Not Reset Recently",
                    "HIGH",
                    f"krbtgt password is {days if days is not None else 'unknown'} days old.",
                    recommendation="Reset krbtgt password twice (with pause) following Microsoft guidance.",
                    risk_score=15,
                    references=[
                        "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password"
                    ],
                )
            )
    return findings, stats


# -- 3. Kerberos ---------------------------------------------------------------


def check_kerberos(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Kerberos")
    kerb = ad.search(
        "(&(objectClass=user)(servicePrincipalName=*)"
        "(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        [
            "sAMAccountName",
            "servicePrincipalName",
            "adminCount",
            "pwdLastSet",
            "userAccountControl",
        ],
    )
    kerb_admin, kerb_stale_pwd, kerb_details, kerb_neverexpire = [], [], [], []
    for u in kerb:
        n = ad.attr_str(u, "sAMAccountName")
        adm = ad.attr_int(u, "adminCount") == 1
        uac = ad.attr_int(u, "userAccountControl")
        pls = _ldap_ts_to_dt(_attr_raw(u, "pwdLastSet"))
        age = _days_since(pls)
        spns = ad.attr_list(u, "servicePrincipalName")
        tag = " [ADMIN]" if adm else ""
        kerb_details.append(f"{n}{tag} -- SPNs: {', '.join(spns[:3])}")
        if adm:
            kerb_admin.append(n)
        if age and age > 365:
            kerb_stale_pwd.append(f"{n} (password age: {age}d)")
        if (uac & UAC_DONT_EXPIRE_PASSWD) and adm:
            kerb_neverexpire.append(n)
    if kerb:
        sev = "CRITICAL" if kerb_admin else "HIGH"
        findings.append(
            F(
                "Kerberos",
                "Kerberoastable Service Accounts",
                sev,
                f"{len(kerb)} user(s) with SPNs can be Kerberoasted offline.",
                details=kerb_details,
                recommendation="Use gMSA accounts, remove unnecessary SPNs, enforce strong passwords (25+ chars).",
                risk_score=20 if sev == "CRITICAL" else 15,
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )
        )
    if kerb_neverexpire:
        findings.append(
            F(
                "Kerberos",
                "High-Value Kerberoast Targets: Admin + SPN + PasswordNeverExpires",
                "CRITICAL",
                f"{len(kerb_neverexpire)} admin service account(s) have SPNs AND non-expiring passwords. "
                "These are the highest-value Kerberoasting targets -- stale RC4 hashes crack easily.",
                details=kerb_neverexpire,
                recommendation="Rotate passwords immediately; migrate to gMSA; remove PasswordNeverExpires.",
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )
        )
    if kerb_stale_pwd:
        findings.append(
            F(
                "Kerberos",
                "Kerberoastable Accounts with Old Passwords",
                "HIGH",
                f"{len(kerb_stale_pwd)} account(s) with SPNs have passwords > 1 year old.",
                details=kerb_stale_pwd,
                recommendation="Rotate service account passwords regularly.",
                risk_score=10,
            )
        )
    stats["kerberoastable"] = len(kerb)
    asrep = ad.search(
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "adminCount"],
    )
    if asrep:
        details = []
        for u in asrep:
            n = ad.attr_str(u, "sAMAccountName")
            adm = ad.attr_int(u, "adminCount") == 1
            details.append(f"{n}" + (" [ADMIN]" if adm else ""))
        findings.append(
            F(
                "Kerberos",
                "AS-REP Roastable Accounts",
                "HIGH",
                f"{len(asrep)} account(s) have Kerberos pre-authentication disabled.",
                details=details,
                recommendation="Enable Kerberos pre-auth on all accounts unless strictly required.",
                risk_score=15,
                references=["https://attack.mitre.org/techniques/T1558/004/"],
            )
        )
    stats["asreproastable"] = len(asrep)
    des = ad.search(
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName"],
    )
    if des:
        findings.append(
            F(
                "Kerberos",
                "Accounts Using DES Encryption Only",
                "HIGH",
                f"{len(des)} account(s) restricted to DES (broken) Kerberos encryption.",
                details=[ad.attr_str(u, "sAMAccountName") for u in des],
                recommendation="Remove 'Use DES encryption types for this account' flag.",
                risk_score=12,
            )
        )
    return findings, stats


# -- 4. Unconstrained Delegation -----------------------------------------------


def check_unconstrained_delegation(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Unconstrained Delegation")
    unc_computers = ad.search(
        "(&(objectClass=computer)"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        ["sAMAccountName", "dNSHostName", "operatingSystem"],
    )
    stats["unconstrained_delegation_computers"] = len(unc_computers)
    if unc_computers:
        details = [
            ad.attr_str(c, "dNSHostName") or ad.attr_str(c, "sAMAccountName")
            for c in unc_computers
        ]
        findings.append(
            F(
                "Delegation",
                "Non-DC Computers with Unconstrained Delegation",
                "CRITICAL",
                f"{len(unc_computers)} computer(s) (excluding DCs) are trusted for unconstrained delegation.",
                details=details,
                recommendation="Remove the 'Trust this computer for delegation to any service' flag. Migrate to RBCD.",
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1134/001/"],
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No Non-DC Computers with Unconstrained Delegation",
                "INFO",
                "Unconstrained delegation is not configured on any non-DC computer.",
                risk_score=0,
            )
        )
    unc_users = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "adminCount"],
    )
    stats["unconstrained_delegation_users"] = len(unc_users)
    if unc_users:
        details = []
        for u in unc_users:
            name = ad.attr_str(u, "sAMAccountName")
            tag = " [ADMIN]" if ad.attr_int(u, "adminCount") == 1 else ""
            details.append(f"{name}{tag}")
        findings.append(
            F(
                "Delegation",
                "User Accounts with Unconstrained Delegation",
                "CRITICAL",
                f"{len(unc_users)} enabled user account(s) are trusted for unconstrained delegation.",
                details=details,
                recommendation="Clear the unconstrained delegation flag from all user accounts.",
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1134/001/"],
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No User Accounts with Unconstrained Delegation",
                "INFO",
                "No enabled user accounts have unconstrained delegation configured.",
                risk_score=0,
            )
        )
    rbcd = ad.search(
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        ["sAMAccountName", "dNSHostName"],
    )
    if rbcd:
        findings.append(
            F(
                "Delegation",
                "Computers with RBCD Configured",
                "INFO",
                f"{len(rbcd)} object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set.",
                details=[
                    ad.attr_str(u, "dNSHostName") or ad.attr_str(u, "sAMAccountName")
                    for u in rbcd
                ],
                recommendation="Verify all RBCD configurations are intentional and minimal.",
                risk_score=0,
            )
        )
    return findings, stats


# -- 5. Constrained Delegation -------------------------------------------------


def check_constrained_delegation(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Constrained Delegation")
    proto_trans = ad.search(
        "(userAccountControl:1.2.840.113556.1.4.803:=16777216)",
        ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectClass", "adminCount"],
    )
    constrained = ad.search(
        "(&(msDS-AllowedToDelegateTo=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=16777216)))",
        ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectClass", "adminCount"],
    )
    stats["constrained_delegation_proto_transition"] = len(proto_trans)
    stats["constrained_delegation_standard"] = len(constrained)
    if proto_trans:
        details = []
        for obj in proto_trans:
            name = ad.attr_str(obj, "sAMAccountName")
            targets = ad.attr_list(obj, "msDS-AllowedToDelegateTo")
            is_user = "computer" not in ad.attr_list(obj, "objectClass")
            tag = " [USER]" if is_user else ""
            adm = " [ADMIN]" if ad.attr_int(obj, "adminCount") == 1 else ""
            details.append(f"{name}{tag}{adm} -> {', '.join(targets[:5])}")
        sev = (
            "CRITICAL"
            if any(
                "computer" not in ad.attr_list(o, "objectClass") for o in proto_trans
            )
            else "HIGH"
        )
        findings.append(
            F(
                "Delegation",
                "Constrained Delegation with Protocol Transition (S4U2Self)",
                sev,
                f"{len(proto_trans)} account(s) have TrustedToAuthForDelegation set.",
                details=details,
                recommendation="Remove TrustedToAuthForDelegation where not strictly required.",
                risk_score=18 if sev == "CRITICAL" else 12,
                references=["https://attack.mitre.org/techniques/T1134/001/"],
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No Protocol Transition (S4U2Self) Delegation Configured",
                "INFO",
                "No accounts have the TrustedToAuthForDelegation flag set.",
                risk_score=0,
            )
        )
    if constrained:
        details = []
        for obj in constrained:
            name = ad.attr_str(obj, "sAMAccountName")
            targets = ad.attr_list(obj, "msDS-AllowedToDelegateTo")
            details.append(f"{name} -> {', '.join(targets[:5])}")
        findings.append(
            F(
                "Delegation",
                "Constrained Delegation Configured",
                "MEDIUM",
                f"{len(constrained)} account(s) have msDS-AllowedToDelegateTo set.",
                details=details,
                recommendation="Audit delegation targets and remove unnecessary entries.",
                risk_score=5,
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No Standard Constrained Delegation Configured",
                "INFO",
                "No accounts have msDS-AllowedToDelegateTo set (without protocol transition).",
                risk_score=0,
            )
        )
    return findings, stats


# -- 6. ADCS -------------------------------------------------------------------


def check_adcs(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] ADCS / PKI")
    pki_base = f"CN=Public Key Services,CN=Services,{ad.config_dn}"
    enroll_base = f"CN=Enrollment Services,{pki_base}"
    tmpl_base = f"CN=Certificate Templates,{pki_base}"
    cas = ad.search(
        "(objectClass=pKIEnrollmentService)",
        ["cn", "dNSHostName", "certificateTemplates", "distinguishedName"],
        base=enroll_base,
    )
    if not cas:
        findings.append(
            F(
                "ADCS",
                "No Certificate Authority Found",
                "INFO",
                "ADCS not detected in this domain.",
                risk_score=0,
            )
        )
        return findings, stats
    stats["cas"] = [ad.attr_str(c, "cn") for c in cas]
    findings.append(
        F(
            "ADCS",
            f"{len(cas)} Certificate Authorit{'y' if len(cas)==1 else 'ies'} Found",
            "INFO",
            f"CAs: {', '.join(stats['cas'])}",
            risk_score=0,
        )
    )
    domain_sid = _get_domain_sid(ad)
    templates = ad.search(
        "(objectClass=pKICertificateTemplate)",
        [
            "cn",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "pKIExtendedKeyUsage",
            "msPKI-Minimal-Key-Size",
            "msPKI-Private-Key-Flag",
            "msPKI-Template-Schema-Version",
            "distinguishedName",
            "msPKI-Cert-Template-OID",
            "nTSecurityDescriptor",
        ],
        base=tmpl_base,
    )
    stats["template_count"] = len(templates)

    def _enrollees(t) -> list:
        dn = ad.attr_str(t, "distinguishedName")
        return _get_template_enrollees(ad, dn, domain_sid) if dn else []

    # ESC1
    esc1 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        if name in _CA_TYPE_TEMPLATES:
            continue
        nf = ad.attr_int(t, "msPKI-Certificate-Name-Flag")
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        ra_sigs = ad.attr_int(t, "msPKI-RA-Signature")
        ekus = set(ad.attr_list(t, "pKIExtendedKeyUsage"))
        approval = bool(ef & CT_FLAG_PEND_ALL_REQUESTS)
        if (
            (nf & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            and (ekus & CLIENT_AUTH or ANY_PURPOSE in ekus or len(ekus) == 0)
            and not approval
            and ra_sigs == 0
        ):
            esc1.append(_fmt_tmpl(name, _enrollees(t)))
    if esc1:
        findings.append(
            F(
                "ADCS",
                "ESC1 - Enrollee-Supplied SAN + Client Auth",
                "CRITICAL",
                f"{len(esc1)} template(s) allow domain privilege escalation via SAN manipulation.",
                details=esc1,
                risk_score=25,
                recommendation="Disable 'Supply in the request' or enable manager approval.",
                references=[
                    "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"
                ],
            )
        )
    # ESC2
    esc2 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        if name in _CA_TYPE_TEMPLATES:
            continue
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        ekus = set(ad.attr_list(t, "pKIExtendedKeyUsage"))
        if (ANY_PURPOSE in ekus or len(ekus) == 0) and not (
            ef & CT_FLAG_PEND_ALL_REQUESTS
        ):
            esc2.append(_fmt_tmpl(name, _enrollees(t)))
    if esc2:
        findings.append(
            F(
                "ADCS",
                "ESC2 - Any Purpose / No EKU Templates",
                "CRITICAL",
                f"{len(esc2)} template(s) with overly broad EKU.",
                details=esc2,
                risk_score=20,
                recommendation="Restrict EKU to specific required purposes only.",
            )
        )
    # ESC3
    esc3 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        ekus = set(ad.attr_list(t, "pKIExtendedKeyUsage"))
        if ENROLL_AGENT in ekus and not (ef & CT_FLAG_PEND_ALL_REQUESTS):
            esc3.append(_fmt_tmpl(name, _enrollees(t)))
    if esc3:
        findings.append(
            F(
                "ADCS",
                "ESC3 - Enrollment Agent Templates",
                "HIGH",
                f"{len(esc3)} enrollment agent template(s) without approval.",
                details=esc3,
                risk_score=15,
                recommendation="Enable manager approval on enrollment agent templates.",
            )
        )
    cert_authorities_base = f"CN=Certification Authorities,{pki_base}"
    # ESC6
    for ca in cas:
        ca_name = ad.attr_str(ca, "cn")
        ca_configs = ad.search(
            f"(&(objectClass=certificationAuthority)(cn={ca_name}))",
            ["flags"],
            base=cert_authorities_base,
        )
        if ca_configs and ad.attr_int(ca_configs[0], "flags") & 0x00040000:
            findings.append(
                F(
                    "ADCS",
                    "ESC6 - CA EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled",
                    "CRITICAL",
                    f"CA '{ca_name}' allows arbitrary SAN on any request.",
                    recommendation=(
                        f"certutil -config '{ca_name}' -setreg policy\\EditFlags "
                        "-EDITF_ATTRIBUTESUBJECTALTNAME2"
                    ),
                    risk_score=25,
                )
            )
    # ESC8
    for ca in cas:
        host = ad.attr_str(ca, "dNSHostName")
        if host:
            try:
                urllib.request.urlopen(f"http://{host}/certsrv/", timeout=3)
                findings.append(
                    F(
                        "ADCS",
                        "ESC8 - HTTP Web Enrollment Endpoint Accessible",
                        "CRITICAL",
                        f"certsrv is available over HTTP on {host} -- NTLM relay to AD CS possible.",
                        recommendation="Enable HTTPS + EPA on certsrv. Disable NTLM where possible.",
                        risk_score=25,
                    )
                )
            except Exception:
                pass
    # ESC9
    esc9 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        ekus = set(ad.attr_list(t, "pKIExtendedKeyUsage"))
        if (ef & CT_FLAG_NO_SECURITY_EXTENSION) and (ekus & CLIENT_AUTH):
            esc9.append(_fmt_tmpl(name, _enrollees(t)))
    if esc9:
        findings.append(
            F(
                "ADCS",
                "ESC9 - No Security Extension",
                "HIGH",
                f"{len(esc9)} client auth template(s) have CT_FLAG_NO_SECURITY_EXTENSION set.",
                details=esc9,
                risk_score=15,
                recommendation="Remove CT_FLAG_NO_SECURITY_EXTENSION from all client auth templates.",
                references=[
                    "https://posts.specterops.io/adcs-esc9-and-esc10-9f3b8427a60f"
                ],
            )
        )
    # ESC10
    client_auth_tmpls = [
        ad.attr_str(t, "cn")
        for t in templates
        if set(ad.attr_list(t, "pKIExtendedKeyUsage")) & CLIENT_AUTH
    ]
    if client_auth_tmpls:
        findings.append(
            F(
                "ADCS",
                "ESC10 - Certificate Mapping Enforcement (Manual)",
                "MEDIUM",
                f"{len(client_auth_tmpls)} client authentication template(s) exist. "
                "If StrongCertificateBindingEnforcement = 0 on DCs, UPN spoofing is possible.",
                details=client_auth_tmpls[:20],
                recommendation=(
                    "Set HKLM\\System\\CurrentControlSet\\Services\\Kdc\\"
                    "StrongCertificateBindingEnforcement = 2 on all DCs."
                ),
                risk_score=8,
                references=[
                    "https://posts.specterops.io/adcs-esc9-and-esc10-9f3b8427a60f"
                ],
            )
        )
    # ESC11
    for ca in cas:
        ca_name = ad.attr_str(ca, "cn")
        ca_configs = ad.search(
            f"(&(objectClass=certificationAuthority)(cn={ca_name}))",
            ["flags"],
            base=cert_authorities_base,
        )
        if ca_configs and ad.attr_int(ca_configs[0], "flags") & 0x00000001:
            findings.append(
                F(
                    "ADCS",
                    "ESC11 - CA Accepts Non-Encrypted RPC Requests",
                    "HIGH",
                    f"CA '{ca_name}' enables NTLM relay over RPC without requiring HTTPS.",
                    recommendation="Enable SSL/TLS on the CA RPC interface.",
                    risk_score=15,
                )
            )
    # ESC13
    esc13 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        ra_sigs = ad.attr_int(t, "msPKI-RA-Signature")
        oid = ad.attr_str(t, "msPKI-Cert-Template-OID")
        if not oid or (ef & CT_FLAG_PEND_ALL_REQUESTS) or ra_sigs != 0:
            continue
        for pol in ad.search(
            f"(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*)(msPKI-Cert-Template-OID={oid}))",
            ["cn", "msDS-OIDToGroupLink"],
            base=pki_base,
        ):
            group_dn = ad.attr_str(pol, "msDS-OIDToGroupLink")
            if group_dn:
                esc13.append(
                    _fmt_tmpl(name, _enrollees(t)) + f" -> linked group: {group_dn}"
                )
    if esc13:
        findings.append(
            F(
                "ADCS",
                "ESC13 - Issuance Policy Linked to AD Group",
                "HIGH",
                f"{len(esc13)} template(s) grant group membership via certificate enrollment.",
                details=esc13,
                risk_score=15,
                recommendation="Audit msDS-OIDToGroupLink on all issuance policy OIDs.",
                references=["https://posts.specterops.io/adcs-esc13-9cfd3ec3d4f9"],
            )
        )
    # ESC15
    esc15 = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        schema_ver = ad.attr_int(t, "msPKI-Template-Schema-Version")
        ef = ad.attr_int(t, "msPKI-Enrollment-Flag")
        nf = ad.attr_int(t, "msPKI-Certificate-Name-Flag")
        ekus = set(ad.attr_list(t, "pKIExtendedKeyUsage"))
        if (
            schema_ver == 1
            and (nf & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            and not (ef & CT_FLAG_PEND_ALL_REQUESTS)
            and (ekus & CLIENT_AUTH)
        ):
            esc15.append(_fmt_tmpl(name, _enrollees(t)))
    if esc15:
        findings.append(
            F(
                "ADCS",
                "ESC15 - Schema Version 1 Template with Enrollee-Supplied SAN",
                "CRITICAL",
                f"{len(esc15)} schema v1 template(s) allow SAN supply and client auth.",
                details=esc15,
                risk_score=25,
                recommendation="Upgrade template schema version or disable enrollee-supplied SAN.",
                references=[
                    "https://posts.specterops.io/adcs-esc15-discover-and-exploit"
                ],
            )
        )
    # Weak key size
    weak_key = []
    for t in templates:
        name = ad.attr_str(t, "cn")
        key_size = ad.attr_int(t, "msPKI-Minimal-Key-Size")
        if key_size and key_size < 2048:
            weak_key.append(f"{name} ({key_size}-bit)")
    if weak_key:
        findings.append(
            F(
                "ADCS",
                "Weak Key Size in Certificate Templates",
                "MEDIUM",
                f"{len(weak_key)} template(s) use key sizes below 2048-bit.",
                details=weak_key,
                risk_score=10,
                recommendation="Require minimum 2048-bit RSA or 256-bit ECC keys.",
            )
        )
    return findings, stats


# -- 7. Domain Trusts ----------------------------------------------------------


def check_trusts(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Domain Trusts")
    trusts = ad.search(
        "(objectClass=trustedDomain)",
        ["name", "trustDirection", "trustType", "trustAttributes"],
    )
    DIRECTION = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
    trust_list = []
    for t in trusts:
        name = ad.attr_str(t, "name")
        dirn = ad.attr_int(t, "trustDirection")
        tattr = ad.attr_int(t, "trustAttributes")
        ds = DIRECTION.get(dirn, "Unknown")
        sid_f = bool(tattr & 0x4)
        forest = bool(tattr & 0x8)
        ext = bool(tattr & 0x10)
        trust_list.append(
            f"{name} ({ds}, SIDFilter={'Y' if sid_f else 'N'}, Forest={forest})"
        )
        if dirn == 3 and not sid_f:
            findings.append(
                F(
                    "Domain Trusts",
                    f"Bidirectional Trust Without SID Filtering: {name}",
                    "HIGH",
                    "SID filtering disabled on bidirectional trust enables SID history attacks.",
                    recommendation="Enable SID filtering: netdom trust /domain:<remote> /EnableSIDHistory:no",
                    risk_score=15,
                )
            )
        if forest and dirn in (2, 3):
            findings.append(
                F(
                    "Domain Trusts",
                    f"Forest Trust to {name}",
                    "MEDIUM",
                    "Forest trusts extend attack surface across forest boundaries.",
                    recommendation="Audit forest trust necessity; enable selective authentication.",
                    risk_score=5,
                )
            )
        if ext:
            findings.append(
                F(
                    "Domain Trusts",
                    f"External Trust to {name}",
                    "MEDIUM",
                    "External trusts are higher risk than forest trusts.",
                    recommendation="Replace with forest trusts or remove if unnecessary.",
                    risk_score=8,
                )
            )
    if trust_list:
        findings.append(
            F(
                "Domain Trusts",
                f"{len(trust_list)} Trust(s) Configured",
                "INFO",
                "Trusts increase attack surface.",
                details=trust_list,
                risk_score=0,
            )
        )
    stats["trusts"] = trust_list
    return findings, stats


# -- 8. Account Hygiene --------------------------------------------------------


def check_account_hygiene(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Account Hygiene")
    now_ldap = int(
        (
            NOW - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        ).total_seconds()
        * 10_000_000
    )
    cutoff_180 = now_ldap - 180 * 864_000_000_000
    cutoff_90 = now_ldap - 90 * 864_000_000_000
    stale_users = ad.search(
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(lastLogonTimestamp<={cutoff_180})(lastLogonTimestamp>=1))",
        ["sAMAccountName", "lastLogonTimestamp"],
    )
    stats["stale_users"] = len(stale_users)
    if len(stale_users) > 10:
        sev = "HIGH" if len(stale_users) > 50 else "MEDIUM"
        details = []
        for u in stale_users[:30]:
            llt = _ldap_ts_to_dt(_attr_raw(u, "lastLogonTimestamp"))
            days = _days_since(llt)
            details.append(
                f"{ad.attr_str(u,'sAMAccountName')} (last logon: {days}d ago)"
            )
        findings.append(
            F(
                "Account Hygiene",
                "Stale Enabled User Accounts (180+ days)",
                sev,
                f"{len(stale_users)} active users haven't logged in for 180+ days.",
                details=details,
                recommendation="Disable accounts after 90 days; delete after 180.",
                risk_score=10,
            )
        )
    stale_comp = ad.search(
        f"(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(lastLogonTimestamp<={cutoff_90})(lastLogonTimestamp>=1))",
        ["sAMAccountName", "lastLogonTimestamp"],
    )
    stats["stale_computers"] = len(stale_comp)
    if len(stale_comp) > 10:
        details = []
        for u in stale_comp[:30]:
            llt = _ldap_ts_to_dt(_attr_raw(u, "lastLogonTimestamp"))
            days = _days_since(llt)
            details.append(
                f"{ad.attr_str(u,'sAMAccountName')} (last auth: {days}d ago)"
            )
        findings.append(
            F(
                "Account Hygiene",
                "Stale Enabled Computer Accounts (90+ days)",
                "MEDIUM",
                f"{len(stale_comp)} computer accounts haven't authenticated for 90+ days.",
                details=details,
                recommendation="Disable stale computer accounts.",
                risk_score=7,
            )
        )
    never = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(lastLogonTimestamp=*)))",
        ["sAMAccountName"],
    )
    if len(never) > 5:
        findings.append(
            F(
                "Account Hygiene",
                "Enabled Users That Have Never Logged In",
                "MEDIUM",
                f"{len(never)} accounts are enabled but have never been used.",
                details=[ad.attr_str(u, "sAMAccountName") for u in never],
                recommendation="Review and disable accounts that have never been used.",
                risk_score=5,
            )
        )
    no_pwd = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName"],
    )
    if no_pwd:
        findings.append(
            F(
                "Account Hygiene",
                "Accounts with 'Password Not Required' Flag",
                "HIGH",
                f"{len(no_pwd)} account(s) can authenticate without a password.",
                details=[ad.attr_str(u, "sAMAccountName") for u in no_pwd],
                recommendation="Remove PASSWD_NOTREQD flag from all accounts.",
                risk_score=15,
            )
        )
    rev_enc = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=128))",
        ["sAMAccountName"],
    )
    if rev_enc:
        findings.append(
            F(
                "Account Hygiene",
                "Accounts with Reversible Encryption Enabled",
                "CRITICAL",
                f"{len(rev_enc)} account(s) store passwords with reversible encryption.",
                details=[ad.attr_str(u, "sAMAccountName") for u in rev_enc],
                recommendation="Disable reversible encryption and reset affected passwords.",
                risk_score=25,
            )
        )
    two_years = now_ldap - 730 * 864_000_000_000
    old_pwd = ad.search(
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(pwdLastSet<={two_years})(pwdLastSet>=1))",
        ["sAMAccountName", "pwdLastSet"],
    )
    if len(old_pwd) > 10:
        details = []
        for u in old_pwd[:30]:
            pls = _ldap_ts_to_dt(_attr_raw(u, "pwdLastSet"))
            age = _days_since(pls)
            details.append(f"{ad.attr_str(u,'sAMAccountName')} (password age: {age}d)")
        findings.append(
            F(
                "Account Hygiene",
                "Many Accounts with Passwords Older Than 2 Years",
                "MEDIUM",
                f"{len(old_pwd)} enabled accounts have not changed passwords in 2+ years.",
                details=details,
                recommendation="Enforce periodic password change.",
                risk_score=5,
            )
        )
    adm_count = ad.search(
        "(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName"],
    )
    stats["admincount1"] = len(adm_count)
    if len(adm_count) > 20:
        findings.append(
            F(
                "Account Hygiene",
                "Excessive adminCount=1 Accounts",
                "MEDIUM",
                f"{len(adm_count)} users have adminCount=1.",
                recommendation="Clear adminCount flag for non-privileged accounts.",
                risk_score=5,
            )
        )
    spn_map: Dict[str, list] = {}
    spn_accs = ad.search(
        "(servicePrincipalName=*)", ["sAMAccountName", "servicePrincipalName"]
    )
    for u in spn_accs:
        for spn in ad.attr_list(u, "servicePrincipalName"):
            spn_map.setdefault(spn.lower(), []).append(ad.attr_str(u, "sAMAccountName"))
    dupes = {s: v for s, v in spn_map.items() if len(v) > 1}
    if dupes:
        findings.append(
            F(
                "Account Hygiene",
                "Duplicate Service Principal Names (SPNs)",
                "HIGH",
                f"{len(dupes)} SPN(s) registered on multiple objects.",
                details=[f"{s}: {', '.join(v)}" for s, v in list(dupes.items())[:20]],
                recommendation="Remove duplicate SPNs: setspn -D <spn> <account>",
                risk_score=10,
            )
        )
    return findings, stats


# -- 9. Protocol Security ------------------------------------------------------


def check_protocols(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Protocol Security")
    if ad.conn.server.ssl:
        findings.append(
            F(
                "Protocol Security",
                "LDAP Signing / Channel Binding",
                "INFO",
                "Connection established over LDAPS (port 636).",
                recommendation="Set LdapEnforceChannelBinding = 2 via registry or GPO on all DCs.",
                risk_score=0,
            )
        )
    else:
        findings.append(
            F(
                "Protocol Security",
                "LDAP Signing / Channel Binding (Manual Verification)",
                "MEDIUM",
                "Cannot read ldapServerIntegrity via LDAP.",
                recommendation="Verify via GPO: 'Domain controller: LDAP server signing requirements' = Require signing.",
                risk_score=8,
            )
        )
    dcs = ad.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "operatingSystem", "operatingSystemVersion", "dNSHostName"],
    )
    dc_list, old_os_dcs = [], []
    for dc in dcs:
        os_name = ad.attr_str(dc, "operatingSystem")
        os_ver = ad.attr_str(dc, "operatingSystemVersion")
        name = ad.attr_str(dc, "dNSHostName") or ad.attr_str(dc, "sAMAccountName")
        dc_list.append(f"{name} - {os_name} {os_ver}")
        if any(old in os_name for old in ("2003", "2008", "2012")):
            old_os_dcs.append(f"{name} ({os_name})")
    stats["domain_controllers"] = dc_list
    if old_os_dcs:
        findings.append(
            F(
                "Protocol Security",
                "Domain Controllers Running End-of-Life OS",
                "CRITICAL",
                f"{len(old_os_dcs)} DC(s) running outdated OS.",
                details=old_os_dcs,
                recommendation="Upgrade DCs to Windows Server 2019/2022.",
                risk_score=20,
            )
        )
    dom = ad.get_domain_object()
    if dom:
        dfl = ad.attr_int(dom, "msDS-Behavior-Version")
        FLS = {
            0: "2000",
            1: "2003 Mixed",
            2: "2003",
            3: "2008",
            4: "2008 R2",
            5: "2012",
            6: "2012 R2",
            7: "2016",
        }
        fl_str = FLS.get(dfl, str(dfl))
        stats["domain_functional_level"] = fl_str
        if dfl < 7:
            sev = "CRITICAL" if dfl < 3 else ("HIGH" if dfl < 5 else "MEDIUM")
            findings.append(
                F(
                    "Protocol Security",
                    f"Domain Functional Level: {fl_str}",
                    sev,
                    f"DFL is {fl_str}. Lower levels lack security features.",
                    recommendation="Raise domain/forest functional level to 2016.",
                    risk_score=15 if dfl < 5 else 8,
                )
            )
    forest_root = ad.search(
        "(objectClass=crossRefContainer)",
        ["msDS-Behavior-Version"],
        base=f"CN=Partitions,{ad.config_dn}",
    )
    if forest_root:
        stats["forest_functional_level"] = ad.attr_int(
            forest_root[0], "msDS-Behavior-Version"
        )
    findings.append(
        F(
            "Protocol Security",
            "NTLMv1 / WDigest (Manual Verification Required)",
            "INFO",
            "NTLMv1 and WDigest settings are registry-only.",
            recommendation="Set LmCompatibilityLevel = 5 and UseLogonCredential = 0 via GPO.",
            risk_score=0,
        )
    )
    return findings, stats


# -- 10. Group Policy Objects --------------------------------------------------


def check_gpo(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Group Policy Objects")
    gpos = ad.search(
        "(objectClass=groupPolicyContainer)",
        [
            "displayName",
            "gPCFileSysPath",
            "flags",
            "distinguishedName",
            "versionNumber",
        ],
    )
    stats["gpo_count"] = len(gpos)
    disabled_gpos, orphaned, low_version = [], [], []
    gpo_dns_by_dn = {}
    for g in gpos:
        dn = ad.attr_str(g, "distinguishedName")
        name = ad.attr_str(g, "displayName") or dn
        flags = ad.attr_int(g, "flags")
        sysvol = ad.attr_str(g, "gPCFileSysPath")
        ver = ad.attr_int(g, "versionNumber")
        gpo_dns_by_dn[dn] = name
        if flags in (1, 2, 3):
            disabled_gpos.append(name)
        if not sysvol:
            orphaned.append(name)
        if ver == 0:
            low_version.append(name)
    linked_gpo_dns = set()
    for obj in ad.search("(gpLink=*)", ["gpLink", "distinguishedName"]):
        for part in ad.attr_str(obj, "gpLink").split("]["):
            part = part.lstrip("[")
            if part.lower().startswith("ldap://"):
                dn_part = part.split(";")[0][7:]
                linked_gpo_dns.add(dn_part.lower())
    unlinked = [
        name
        for dn, name in gpo_dns_by_dn.items()
        if dn.lower() not in linked_gpo_dns and name not in disabled_gpos
    ]
    stats["gpo_disabled"] = len(disabled_gpos)
    stats["gpo_orphaned"] = len(orphaned)
    stats["gpo_unlinked"] = len(unlinked)
    stats["gpo_empty"] = len(low_version)
    if len(gpos) > 100:
        findings.append(
            F(
                "Group Policy",
                "Excessive Number of GPOs",
                "LOW",
                f"{len(gpos)} GPOs detected.",
                recommendation="Consolidate overlapping GPOs.",
                risk_score=3,
            )
        )
    for cond, label, desc, rec in [
        (
            disabled_gpos,
            "Disabled GPOs Present",
            "fully or partially disabled",
            "Remove permanently disabled GPOs.",
        ),
        (
            orphaned,
            "Orphaned GPO Objects (No SYSVOL Path)",
            "have no associated SYSVOL path",
            "Run gpotool.exe /checkacl.",
        ),
        (
            unlinked,
            "Unlinked GPOs",
            "not linked to any OU, domain, or site",
            "Review and delete intentionally unused GPOs.",
        ),
        (
            low_version,
            "Empty / Never-Edited GPOs",
            "have a version number of 0",
            "Delete empty GPOs.",
        ),
    ]:
        if cond:
            findings.append(
                F(
                    "Group Policy",
                    label,
                    (
                        "INFO"
                        if "Orphan" not in label and "Unlinked" not in label
                        else "LOW"
                    ),
                    f"{len(cond)} GPO(s) {desc}.",
                    details=cond[:30],
                    recommendation=rec,
                    risk_score=2 if "Orphan" in label else 0,
                )
            )
        else:
            findings.append(
                F("Group Policy", f"No {label}", "INFO", "None found.", risk_score=0)
            )
    return findings, stats


# -- 11. LAPS ------------------------------------------------------------------


def check_laps(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] LAPS")
    laps_attr = ad.search("(cn=ms-Mcs-AdmPwd)", ["cn"], base=ad.schema_dn)
    laps_v2_attr = ad.search("(cn=ms-LAPS-Password)", ["cn"], base=ad.schema_dn)
    has_laps = bool(laps_attr)
    has_laps_v2 = bool(laps_v2_attr)
    stats["laps_installed"] = has_laps
    stats["laps_v2_installed"] = has_laps_v2
    if not has_laps and not has_laps_v2:
        findings.append(
            F(
                "LAPS",
                "LAPS Not Installed",
                "HIGH",
                "Local Administrator Password Solution is not deployed.",
                recommendation="Deploy Windows LAPS (built-in to Server 2019/Win11) or legacy LAPS.",
                risk_score=15,
            )
        )
        return findings, stats
    version = "Windows LAPS (v2)" if has_laps_v2 else "Legacy LAPS"
    findings.append(
        F(
            "LAPS",
            f"{version} Schema Detected",
            "INFO",
            f"{version} schema attributes are present.",
            risk_score=0,
        )
    )
    if has_laps:
        no_laps = ad.search(
            "(&(objectClass=computer)(!(ms-Mcs-AdmPwd=*))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        if no_laps:
            findings.append(
                F(
                    "LAPS",
                    "Computers Without LAPS Password",
                    "MEDIUM",
                    f"{len(no_laps)} enabled computer(s) have no LAPS password set.",
                    details=[ad.attr_str(u, "sAMAccountName") for u in no_laps[:30]],
                    recommendation="Ensure LAPS is applied to all workstations/servers.",
                    risk_score=10,
                )
            )
    if has_laps_v2:
        no_lapsv2 = ad.search(
            "(&(objectClass=computer)(!(ms-LAPS-Password=*))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        if no_lapsv2:
            findings.append(
                F(
                    "LAPS",
                    "Computers Without Windows LAPS Password",
                    "MEDIUM",
                    f"{len(no_lapsv2)} computer(s) lack Windows LAPS password attributes.",
                    details=[ad.attr_str(u, "sAMAccountName") for u in no_lapsv2[:30]],
                    recommendation="Deploy Windows LAPS policy to all machines.",
                    risk_score=10,
                )
            )
    return findings, stats


# -- 12. LAPS Coverage ---------------------------------------------------------


def check_laps_coverage(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] LAPS Password Coverage")
    has_legacy = bool(ad.search("(cn=ms-Mcs-AdmPwd)", ["cn"], base=ad.schema_dn))
    has_winlaps = bool(ad.search("(cn=ms-LAPS-Password)", ["cn"], base=ad.schema_dn))
    stats["laps_legacy_schema"] = has_legacy
    stats["laps_winlaps_schema"] = has_winlaps
    if not has_legacy and not has_winlaps:
        return findings, stats
    all_computers = ad.search(
        "(&(objectClass=computer)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        [
            "sAMAccountName",
            "ms-Mcs-AdmPwd",
            "ms-LAPS-Password",
            "ms-LAPS-EncryptedPassword",
            "operatingSystem",
        ],
    )
    no_laps, covered = [], []
    for c in all_computers:
        name = ad.attr_str(c, "sAMAccountName")
        has_pwd = (
            bool(ad.attr_str(c, "ms-Mcs-AdmPwd"))
            or bool(ad.attr_str(c, "ms-LAPS-Password"))
            or bool(ad.attr_str(c, "ms-LAPS-EncryptedPassword"))
        )
        if has_pwd:
            covered.append(name)
        else:
            no_laps.append(
                f"{name} ({ad.attr_str(c,'operatingSystem') or 'OS unknown'})"
            )
    total = len(all_computers)
    stats["laps_covered"] = len(covered)
    stats["laps_missing"] = len(no_laps)
    stats["laps_total_hosts"] = total
    if no_laps:
        pct = int(100 * len(no_laps) / total) if total else 0
        sev = "HIGH" if pct > 20 else "MEDIUM"
        findings.append(
            F(
                "LAPS",
                "Computers Without a LAPS Password Set",
                sev,
                f"{len(no_laps)} of {total} enabled non-DC computer(s) ({pct}%) have no LAPS password.",
                details=no_laps[:50],
                recommendation="Apply a LAPS GPO to all workstations and servers.",
                risk_score=12 if sev == "HIGH" else 7,
            )
        )
    else:
        findings.append(
            F(
                "LAPS",
                "LAPS Password Present on All Non-DC Computers",
                "INFO",
                f"All {total} enabled non-DC computer(s) have a LAPS password set.",
                risk_score=0,
            )
        )
    return findings, stats


# -- 13. DNS -------------------------------------------------------------------


def check_dns(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] DNS & Infrastructure")
    dns_zones = ad.search(
        "(objectClass=dnsZone)",
        ["name"],
        base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{ad.base_dn}",
    )
    stats["dns_zones"] = [ad.attr_str(z, "name") for z in dns_zones]
    for r in dns_zones:
        if "*" in ad.attr_str(r, "name"):
            findings.append(
                F(
                    "DNS",
                    "Wildcard DNS Record Detected",
                    "HIGH",
                    "Wildcard DNS entry found.",
                    recommendation="Remove wildcard DNS records unless specifically required.",
                    risk_score=10,
                )
            )
    dns_servers = ad.search(
        "(objectClass=dnsNode)",
        ["dc", "dnsRecord"],
        base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{ad.base_dn}",
    )
    stats["dns_record_count"] = len(dns_servers)
    findings.append(
        F(
            "DNS",
            "LLMNR / NetBIOS-NS Poisoning (Manual Check Required)",
            "INFO",
            "LLMNR and NetBIOS-NS enable Responder-style credential capture.",
            recommendation="Disable LLMNR via GPO and NetBIOS over TCP/IP on all adapters.",
            risk_score=0,
        )
    )
    return findings, stats


# -- 14. Domain Controllers ----------------------------------------------------


def check_domain_controllers(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Domain Controllers")
    dcs = ad.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        [
            "sAMAccountName",
            "operatingSystem",
            "dNSHostName",
            "lastLogonTimestamp",
            "userAccountControl",
        ],
    )
    stats["dc_count"] = len(dcs)
    if len(dcs) == 1:
        findings.append(
            F(
                "Domain Controllers",
                "Single Domain Controller Detected",
                "HIGH",
                "Only one DC -- single point of failure.",
                recommendation="Deploy at least two DCs for redundancy.",
                risk_score=10,
            )
        )
    old_os = []
    for dc in dcs:
        os_n = ad.attr_str(dc, "operatingSystem")
        name = ad.attr_str(dc, "dNSHostName") or ad.attr_str(dc, "sAMAccountName")
        if any(v in os_n for v in ("2003", "2000", "2008")):
            old_os.append(f"{name} ({os_n})")
    if old_os:
        findings.append(
            F(
                "Domain Controllers",
                "Legacy OS on Domain Controllers",
                "CRITICAL",
                f"{len(old_os)} DC(s) running end-of-life Windows Server.",
                details=old_os,
                recommendation="Upgrade to Server 2019/2022 immediately.",
                risk_score=25,
            )
        )
    fsmo = ad.search("(fSMORoleOwner=*)", ["fSMORoleOwner", "cn"])
    stats["fsmo_roles"] = [ad.attr_str(f, "cn") for f in fsmo]
    rodcs = ad.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))",
        ["sAMAccountName", "msDS-RevealOnDemandGroup"],
    )
    for r in rodcs:
        rname = ad.attr_str(r, "sAMAccountName")
        reveal = ad.attr_list(r, "msDS-RevealOnDemandGroup")
        if any("Domain Users" in x or "Authenticated Users" in x for x in reveal):
            findings.append(
                F(
                    "Domain Controllers",
                    f"RODC {rname} Has Broad Password Replication",
                    "HIGH",
                    "RODC caches passwords for all domain users.",
                    recommendation="Restrict msDS-RevealOnDemandGroup to only users who log into that RODC.",
                    risk_score=12,
                )
            )
    stats["rodc_count"] = len(rodcs)
    return findings, stats


# -- 15. ACL / Permissions -----------------------------------------------------


def check_acls(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] ACL / Permissions")
    from ldap3 import SUBTREE
    from ldap3.protocol.microsoft import security_descriptor_control

    domain_sid = _get_domain_sid(ad)

    def _get_sd(dn, obj_filter="(objectClass=*)", attrs=None):
        a = (attrs or []) + ["nTSecurityDescriptor"]
        try:
            ctrl = security_descriptor_control(sdflags=0x04)
            ad.conn.search(
                search_base=dn,
                search_filter=obj_filter,
                search_scope=SUBTREE,
                attributes=a,
                controls=ctrl,
                size_limit=500,
            )
            return ad.conn.entries
        except Exception as e:
            print(f"  [~] SD fetch failed ({dn[:50]}): {e}")
            return []

    # ESC4
    tmpl_base = (
        f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{ad.config_dn}"
    )
    esc4_by_trustee: Dict[str, set] = {}
    for t in _get_sd(tmpl_base, "(objectClass=pKICertificateTemplate)", ["cn"]):
        tname = ad.attr_str(t, "cn")
        sd_attr = getattr(t, "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            continue
        for ace in _parse_sd(raw_sd):
            sid = ace["trustee_sid"]
            mask = ace["access_mask"]
            if ace["ace_type"] not in (0x00, 0x05):
                continue
            if _sid_is_privileged(sid, domain_sid):
                continue
            if mask & (
                AM_GENERIC_ALL | AM_WRITE_DACL | AM_WRITE_OWNER | AM_GENERIC_WRITE
            ):
                esc4_by_trustee.setdefault(ad.resolve_sid(sid), set()).add(tname)
    if esc4_by_trustee:
        details = [
            f"{t} -> {', '.join(sorted(tmpls))}"
            for t, tmpls in sorted(esc4_by_trustee.items())
        ]
        findings.append(
            F(
                "ADCS",
                "ESC4 - Writable Certificate Template ACLs",
                "CRITICAL",
                f"{sum(len(v) for v in esc4_by_trustee.values())} template/trustee combination(s).",
                details=details,
                recommendation="Remove GenericAll, WriteDACL, WriteOwner, GenericWrite from non-privileged accounts.",
                risk_score=25,
                references=[
                    "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"
                ],
            )
        )
    else:
        findings.append(
            F(
                "ADCS",
                "ESC4 - Certificate Template ACLs",
                "INFO",
                "No misconfigured template ACLs detected.",
                risk_score=0,
            )
        )
    # ESC5
    pki_base = f"CN=Public Key Services,CN=Services,{ad.config_dn}"
    esc5_by_trustee: Dict[str, set] = {}
    for obj in _get_sd(pki_base, "(objectClass=*)", ["cn", "distinguishedName"]):
        oname = ad.attr_str(obj, "cn") or ad.attr_str(obj, "distinguishedName")
        sd_attr = getattr(obj, "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            continue
        seen_sids = set()
        for ace in _parse_sd(raw_sd):
            sid = ace["trustee_sid"]
            mask = ace["access_mask"]
            if ace["ace_type"] not in (0x00, 0x05):
                continue
            if _sid_is_privileged(sid, domain_sid):
                continue
            if _sid_is_dc(sid, ad):
                continue
            if sid in seen_sids:
                continue
            if mask & (
                AM_GENERIC_ALL | AM_WRITE_DACL | AM_WRITE_OWNER | AM_GENERIC_WRITE
            ):
                seen_sids.add(sid)
                esc5_by_trustee.setdefault(ad.resolve_sid(sid), set()).add(oname)
    if esc5_by_trustee:
        details = [
            f"{t} -> {', '.join(sorted(objs))}"
            for t, objs in sorted(esc5_by_trustee.items())
        ]
        findings.append(
            F(
                "ADCS",
                "ESC5 - Writable PKI Object ACLs",
                "CRITICAL",
                f"{len(esc5_by_trustee)} non-privileged principal(s) have write access to PKI container objects.",
                details=details,
                recommendation="Remove write permissions from non-admin accounts on all PKI container objects.",
                risk_score=25,
                references=[
                    "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"
                ],
            )
        )
    else:
        findings.append(
            F(
                "ADCS",
                "ESC5 - PKI Object ACLs",
                "INFO",
                "No non-privileged write access on PKI container objects.",
                risk_score=0,
            )
        )
    # ESC7
    enroll_base = (
        f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{ad.config_dn}"
    )
    esc7_by_trustee: Dict[str, list] = {}
    for ca in _get_sd(enroll_base, "(objectClass=pKIEnrollmentService)", ["cn"]):
        cname = ad.attr_str(ca, "cn")
        sd_attr = getattr(ca, "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            continue
        for ace in _parse_sd(raw_sd):
            sid = ace["trustee_sid"]
            mask = ace["access_mask"]
            if ace["ace_type"] not in (0x00, 0x05):
                continue
            if _sid_is_privileged(sid, domain_sid):
                continue
            if _sid_is_dc(sid, ad):
                continue
            if mask & (
                CA_MANAGE | CA_OFFICER | AM_GENERIC_ALL | AM_WRITE_DACL | AM_WRITE_OWNER
            ):
                esc7_by_trustee.setdefault(ad.resolve_sid(sid), []).append(cname)
    if esc7_by_trustee:
        details = [
            f"{t} -> {', '.join(cas)}" for t, cas in sorted(esc7_by_trustee.items())
        ]
        findings.append(
            F(
                "ADCS",
                "ESC7 - CA Officer/Manager Rights for Low-Privileged Users",
                "CRITICAL",
                f"{len(esc7_by_trustee)} non-privileged principal(s) have CA Officer or Manager rights.",
                details=details,
                recommendation="Remove ManageCertificates/ManageCA rights from non-admin accounts.",
                risk_score=20,
                references=[
                    "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"
                ],
            )
        )
    else:
        findings.append(
            F(
                "ADCS",
                "ESC7 - CA Officer/Manager ACL",
                "INFO",
                "No low-privileged CA Officer/Manager rights detected.",
                risk_score=0,
            )
        )
    # DCSync
    REPL_GUIDS = {
        REPL_GET_CHANGES_ALL: "DS-Replication-Get-Changes-All",
        REPL_GET_CHANGES: "DS-Replication-Get-Changes",
        REPL_GET_CHANGES_FIL: "DS-Replication-Get-Changes-In-Filtered-Set",
    }
    dcsync_by_trustee: Dict[str, list] = {}
    for dom in _get_sd(ad.base_dn, "(objectClass=domain)", ["distinguishedName"]):
        sd_attr = getattr(dom, "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            continue
        for ace in _parse_sd(raw_sd):
            if ace["ace_type"] != 0x05:
                continue
            sid = ace["trustee_sid"]
            otype = (ace.get("object_type") or "").lower().strip()
            if _sid_is_privileged(sid, domain_sid):
                continue
            if otype in REPL_GUIDS:
                dcsync_by_trustee.setdefault(ad.resolve_sid(sid), []).append(
                    REPL_GUIDS[otype]
                )
    if dcsync_by_trustee:
        details = [
            f"{t} -> {', '.join(r)}" for t, r in sorted(dcsync_by_trustee.items())
        ]
        findings.append(
            F(
                "DCSync",
                "Non-Privileged Accounts with DCSync Rights",
                "CRITICAL",
                f"{len(dcsync_by_trustee)} non-privileged principal(s) have replication rights.",
                details=details,
                recommendation="Remove DS-Replication-Get-Changes-All from non-DC/non-DA accounts immediately.",
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1003/006/"],
            )
        )
    else:
        findings.append(
            F(
                "DCSync",
                "DCSync Rights",
                "INFO",
                "No unexpected DCSync rights detected.",
                risk_score=0,
            )
        )
    # Protected Users
    pu = ad.search(
        f"(&(objectClass=user)(memberOf=CN=Protected Users,CN=Users,{ad.base_dn}))",
        ["sAMAccountName"],
    )
    stats["protected_users_group"] = len(pu)
    if len(pu) == 0:
        findings.append(
            F(
                "ACL",
                "No Users in Protected Users Group",
                "MEDIUM",
                "The Protected Users group provides extra Kerberos protections.",
                recommendation="Add all privileged accounts to the Protected Users group.",
                risk_score=8,
            )
        )
    deleg = ad.search(
        "(msDS-AllowedToDelegateTo=*)",
        ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectClass"],
    )
    if deleg:
        risky = []
        for d in deleg:
            if "computer" not in ad.attr_list(d, "objectClass"):
                targets = ad.attr_list(d, "msDS-AllowedToDelegateTo")[:2]
                risky.append(
                    f"{ad.attr_str(d,'sAMAccountName')} -> {', '.join(targets)}"
                )
        if risky:
            findings.append(
                F(
                    "ACL",
                    "User Accounts with Constrained Delegation Configured",
                    "MEDIUM",
                    f"{len(risky)} non-computer account(s) have delegation targets.",
                    details=risky[:20],
                    recommendation="Verify delegation targets are intentional and minimal.",
                    risk_score=8,
                )
            )
    stats["protected_users_count"] = len(pu)
    return findings, stats


# -- 16. Optional Features -----------------------------------------------------


def check_optional_features(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Optional Features")
    opt_feat = ad.search(
        "(objectClass=msDS-OptionalFeature)",
        ["name", "msDS-OptionalFeatureFlags"],
        base=f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{ad.config_dn}",
    )
    has_recycle = any("Recycle Bin" in ad.attr_str(f, "name") for f in opt_feat)
    stats["recycle_bin_enabled"] = has_recycle
    if not has_recycle:
        findings.append(
            F(
                "Optional Features",
                "AD Recycle Bin Not Enabled",
                "LOW",
                "Deleted AD objects cannot be easily recovered.",
                recommendation="Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet",
                risk_score=3,
            )
        )
    has_pam = any(
        "Privileged Access Management" in ad.attr_str(f, "name") for f in opt_feat
    )
    stats["pam_enabled"] = has_pam
    if not has_pam:
        findings.append(
            F(
                "Optional Features",
                "Privileged Access Management (PAM) Not Enabled",
                "INFO",
                "PAM enables time-based, just-in-time privileged access.",
                recommendation="Consider enabling PAM for enhanced privileged access management.",
                risk_score=0,
            )
        )
    return findings, stats


# -- 17. Replication Health ----------------------------------------------------


def check_replication(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Replication Health")
    sites = ad.search("(objectClass=site)", ["cn"], base=f"CN=Sites,{ad.config_dn}")
    stats["site_count"] = len(sites)
    if len(sites) > 1:
        findings.append(
            F(
                "Replication",
                f"{len(sites)} AD Sites Detected",
                "INFO",
                "Multi-site topology -- verify site links and replication schedules.",
                details=[ad.attr_str(s, "cn") for s in sites],
                risk_score=0,
            )
        )
    site_links = ad.search(
        "(objectClass=siteLink)",
        ["cn", "cost", "replInterval"],
        base=f"CN=IP,CN=Inter-Site Transports,CN=Sites,{ad.config_dn}",
    )
    for sl in site_links:
        interval = ad.attr_int(sl, "replInterval")
        if interval > 180:
            findings.append(
                F(
                    "Replication",
                    "Site Link Replication Interval Too High",
                    "MEDIUM",
                    f"Site link '{ad.attr_str(sl,'cn')}' has interval of {interval} minutes.",
                    recommendation="Set replication interval to <= 60 minutes.",
                    risk_score=3,
                )
            )
    ntds_objects = ad.search(
        "(objectClass=nTDSDSA)",
        ["distinguishedName", "options"],
        base=f"CN=Sites,{ad.config_dn}",
    )
    stats["ntdsdsa_count"] = len(ntds_objects)
    if len(ntds_objects) == 0:
        findings.append(
            F(
                "Replication",
                "No nTDSDSA Objects Found",
                "HIGH",
                "Could not find any DC replication service objects.",
                recommendation="Run: repadmin /showrepl and dcdiag /test:replications",
                risk_score=10,
            )
        )
    return findings, stats


# -- 18. Service Accounts ------------------------------------------------------


def check_service_accounts(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Service Accounts & gMSA")
    gmsa = ad.search(
        "(objectClass=msDS-GroupManagedServiceAccount)", ["sAMAccountName"]
    )
    smsa = ad.search("(objectClass=msDS-ManagedServiceAccount)", ["sAMAccountName"])
    stats["gmsa_count"] = len(gmsa)
    stats["smsa_count"] = len(smsa)
    svc = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "pwdLastSet", "adminCount"],
    )
    stats["regular_service_accounts"] = len(svc)
    if len(svc) > 0 and len(gmsa) == 0:
        findings.append(
            F(
                "Service Accounts",
                "No gMSA In Use -- Regular Accounts Have SPNs",
                "HIGH",
                f"{len(svc)} regular user account(s) used as service accounts, but no gMSA deployed.",
                details=[ad.attr_str(u, "sAMAccountName") for u in svc],
                recommendation="Migrate service accounts to Group Managed Service Accounts (gMSA).",
                risk_score=10,
            )
        )
    elif len(svc) > 0:
        findings.append(
            F(
                "Service Accounts",
                f"{len(svc)} Regular User Service Accounts (Non-gMSA)",
                "MEDIUM",
                f"{len(svc)} accounts with SPNs are not gMSA.",
                details=[ad.attr_str(u, "sAMAccountName") for u in svc],
                recommendation="Migrate to gMSA where possible.",
                risk_score=5,
            )
        )
    svc_admin = [
        ad.attr_str(u, "sAMAccountName")
        for u in svc
        if ad.attr_int(u, "adminCount") == 1
    ]
    if svc_admin:
        findings.append(
            F(
                "Service Accounts",
                "Service Accounts with adminCount=1",
                "HIGH",
                f"{len(svc_admin)} service account(s) have adminCount=1.",
                details=svc_admin,
                recommendation="Remove service accounts from privileged groups.",
                risk_score=12,
            )
        )
    return findings, stats


# -- 19. Miscellaneous Hardening -----------------------------------------------


def check_misc(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Miscellaneous Hardening")
    dom = ad.get_domain_object()
    if dom:
        maq = ad.attr_int(dom, "ms-DS-MachineAccountQuota")
        stats["machine_account_quota"] = maq
        if maq > 0:
            findings.append(
                F(
                    "Hardening",
                    "Machine Account Quota > 0",
                    "MEDIUM",
                    f"ms-DS-MachineAccountQuota = {maq}. Any domain user can add up to {maq} computers.",
                    recommendation="Set ms-DS-MachineAccountQuota to 0.",
                    risk_score=10,
                )
            )
    ts_entries = ad.search(
        "(objectClass=nTDSService)",
        ["tombstoneLifetime"],
        base=f"CN=Directory Service,CN=Windows NT,CN=Services,{ad.config_dn}",
    )
    if ts_entries:
        tsl = ad.attr_int(ts_entries[0], "tombstoneLifetime") or 60
        stats["tombstone_lifetime"] = tsl
        if tsl < 180:
            findings.append(
                F(
                    "Hardening",
                    "Short Tombstone Lifetime",
                    "LOW",
                    f"Tombstone lifetime is {tsl} days.",
                    recommendation="Set tombstone lifetime to 180 days.",
                    risk_score=2,
                )
            )
    schema_admins = ad.search(
        f"(&(objectClass=user)(memberOf=CN=Schema Admins,CN=Users,{ad.base_dn}))",
        ["sAMAccountName"],
    )
    if len(schema_admins) > 1:
        findings.append(
            F(
                "Hardening",
                "Schema Admins Group Has Members",
                "HIGH",
                f"{len(schema_admins)} member(s) in Schema Admins.",
                details=[ad.attr_str(u, "sAMAccountName") for u in schema_admins],
                recommendation="Remove all members from Schema Admins immediately after schema updates.",
                risk_score=15,
            )
        )
    ent_admins = ad.search(
        f"(&(objectClass=user)(memberOf=CN=Enterprise Admins,CN=Users,{ad.base_dn}))",
        ["sAMAccountName"],
    )
    if len(ent_admins) > 1:
        findings.append(
            F(
                "Hardening",
                "Enterprise Admins Group Has Members",
                "HIGH",
                f"{len(ent_admins)} member(s) in Enterprise Admins.",
                details=[ad.attr_str(u, "sAMAccountName") for u in ent_admins],
                recommendation="Remove non-essential accounts from Enterprise Admins.",
                risk_score=12,
            )
        )
    guest = ad.search(
        "(&(objectClass=user)(sAMAccountName=Guest))", ["userAccountControl"]
    )
    if guest and not (ad.attr_int(guest[0], "userAccountControl") & UAC_DISABLED):
        findings.append(
            F(
                "Hardening",
                "Guest Account Enabled",
                "MEDIUM",
                "The built-in Guest account is enabled.",
                recommendation="Disable the Guest account.",
                risk_score=8,
            )
        )
    findings.append(
        F(
            "Hardening",
            "Advanced Audit Policy (Manual GPO Verification)",
            "INFO",
            "Ensure Advanced Audit Policy covers: Logon/Logoff, Account Management, Directory Service Access.",
            recommendation="Configure via GPO: Computer Config > Security Settings > Advanced Audit.",
            risk_score=0,
        )
    )
    return findings, stats


# -- 20. Deprecated Operating Systems -----------------------------------------


def check_deprecated_os(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Deprecated Operating Systems")
    computers = ad.search(
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        [
            "sAMAccountName",
            "dNSHostName",
            "operatingSystem",
            "operatingSystemVersion",
            "lastLogonTimestamp",
        ],
    )
    deprecated = []
    for c in computers:
        os_name = ad.attr_str(c, "operatingSystem")
        if not os_name:
            continue
        if any(p in os_name.lower() for p in DEPRECATED_OS_PATTERNS):
            llt = _ldap_ts_to_dt(_attr_raw(c, "lastLogonTimestamp"))
            days = _days_since(llt)
            host = ad.attr_str(c, "dNSHostName") or ad.attr_str(c, "sAMAccountName")
            age_str = f"{days}d ago" if days is not None else "never/unknown"
            deprecated.append(f"{host} -- {os_name} (last auth: {age_str})")
    stats["deprecated_os_count"] = len(deprecated)
    if deprecated:
        findings.append(
            F(
                "Deprecated OS",
                "Computer Accounts Running Deprecated Operating Systems",
                "CRITICAL",
                f"{len(deprecated)} enabled computer account(s) report a deprecated OS.",
                details=deprecated,
                recommendation="Decommission or isolate deprecated systems immediately.",
                risk_score=20,
            )
        )
    else:
        findings.append(
            F(
                "Deprecated OS",
                "No Deprecated Operating Systems Detected",
                "INFO",
                "All enabled computer accounts report a currently-supported OS.",
                risk_score=0,
            )
        )
    return findings, stats


# -- 21. Legacy Protocols ------------------------------------------------------


def check_legacy_protocols(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Legacy Protocol Exposure")
    legacy = ad.search(
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "operatingSystem", "lastLogonTimestamp"],
    )
    legacy_os = []
    for c in legacy:
        os_n = ad.attr_str(c, "operatingSystem").lower()
        name = ad.attr_str(c, "sAMAccountName")
        if any(
            v in os_n
            for v in ("xp", "vista", "windows 7", "windows 8", "2003", "2000", "nt 4")
        ):
            llt = _ldap_ts_to_dt(_attr_raw(c, "lastLogonTimestamp"))
            days = _days_since(llt)
            if days is None or days < 180:
                legacy_os.append(f"{name} ({ad.attr_str(c,'operatingSystem')})")
    if legacy_os:
        findings.append(
            F(
                "Legacy Protocols",
                "Active Legacy Windows Systems Detected",
                "CRITICAL",
                f"{len(legacy_os)} computer(s) running end-of-life OS are actively authenticating.",
                details=legacy_os[:30],
                recommendation="Decommission or isolate legacy systems.",
                risk_score=20,
            )
        )
    stats["legacy_os_count"] = len(legacy_os)
    smb1_hosts, signing_issues, null_sessions = _check_smb1_hosts(ad)
    if smb1_hosts:
        sev = "CRITICAL" if any(ad.dc_ip in h for h in smb1_hosts) else "HIGH"
        findings.append(
            F(
                "Legacy Protocols",
                "SMBv1 Enabled on Active Hosts",
                sev,
                f"{len(smb1_hosts)} host(s) responded positively to an SMBv1 negotiate request.",
                details=smb1_hosts,
                recommendation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                risk_score=20 if sev == "CRITICAL" else 15,
                references=["https://aka.ms/stopusingsmb1"],
            )
        )
    else:
        findings.append(
            F(
                "Legacy Protocols",
                "SMBv1 Not Detected on Probed Hosts",
                "INFO",
                "No hosts responded to SMBv1 negotiate requests.",
                risk_score=0,
            )
        )
    if signing_issues:
        sev = "CRITICAL" if any(ad.dc_ip in h for h in signing_issues) else "HIGH"
        findings.append(
            F(
                "Legacy Protocols",
                "SMB Signing Not Required or Disabled",
                sev,
                f"{len(signing_issues)} host(s) have SMB signing disabled or not required.",
                details=signing_issues,
                recommendation="Enforce SMB signing via GPO: 'Microsoft network server: Digitally sign communications (always)'",
                risk_score=20 if sev == "CRITICAL" else 15,
                references=["https://attack.mitre.org/techniques/T1557/001/"],
            )
        )
    else:
        findings.append(
            F(
                "Legacy Protocols",
                "SMB Signing Required on All Probed Hosts",
                "INFO",
                "All reachable hosts require SMB signing.",
                risk_score=0,
            )
        )
    if null_sessions:
        sev = "CRITICAL" if any(ad.dc_ip in h for h in null_sessions) else "HIGH"
        findings.append(
            F(
                "Legacy Protocols",
                "Null Sessions Accepted",
                sev,
                f"{len(null_sessions)} host(s) accept unauthenticated SMB null sessions.",
                details=null_sessions,
                recommendation="Set RestrictNullSessAccess = 1 via GPO.",
                risk_score=20 if sev == "CRITICAL" else 15,
                references=["https://attack.mitre.org/techniques/T1135/"],
            )
        )
    else:
        findings.append(
            F(
                "Legacy Protocols",
                "Null Sessions Not Accepted on Probed Hosts",
                "INFO",
                "No hosts accepted unauthenticated null session requests.",
                risk_score=0,
            )
        )
    return findings, stats


# -- 22. Exchange --------------------------------------------------------------


def check_exchange(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Exchange / Mail Permissions")
    exch = ad.search(
        "(&(objectClass=container)(cn=Microsoft Exchange))", ["cn"], base=ad.config_dn
    )
    if not exch:
        exch = ad.search(
            "(cn=ms-Exch-Configuration-Container)", ["cn"], base=ad.schema_dn
        )
    if not exch:
        findings.append(
            F(
                "Exchange",
                "Exchange Not Detected",
                "INFO",
                "No Exchange organization container found.",
                risk_score=0,
            )
        )
        return findings, stats
    stats["exchange_present"] = True
    ewp = ad.search(
        "(&(objectClass=group)(cn=Exchange Windows Permissions))", ["member"]
    )
    if ewp:
        members = ad.attr_list(ewp[0], "member")
        if members:
            findings.append(
                F(
                    "Exchange",
                    "Exchange Windows Permissions Group Has Members",
                    "HIGH",
                    f"{len(members)} member(s) in 'Exchange Windows Permissions'. "
                    "This group has WriteDACL on the domain object (PrivExchange / CVE-2019-0686).",
                    recommendation="Apply Exchange Split Permissions model.",
                    risk_score=15,
                    references=[
                        "https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/"
                    ],
                )
            )
    ets = ad.search("(&(objectClass=group)(cn=Exchange Trusted Subsystem))", ["member"])
    if ets:
        members = ad.attr_list(ets[0], "member")
        if members:
            findings.append(
                F(
                    "Exchange",
                    "Exchange Trusted Subsystem Has Members",
                    "MEDIUM",
                    f"Exchange Trusted Subsystem has {len(members)} member(s).",
                    recommendation="Ensure only Exchange server computer accounts are members.",
                    risk_score=8,
                )
            )
    return findings, stats


# -- 23. Protected Admin Users (adminCount=1) -----------------------------------


def check_admin_count(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Protected Admin Users (adminCount=1)")
    priv_groups = _priv_group_dns(ad.base_dn)
    admin_count_users = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1))",
        [
            "sAMAccountName",
            "userAccountControl",
            "memberOf",
            "lastLogonTimestamp",
            "pwdLastSet",
        ],
    )
    stats["admincount1_total"] = len(admin_count_users)
    disabled_admins, stale_admins, orphan_admins = [], [], []
    for u in admin_count_users:
        name = ad.attr_str(u, "sAMAccountName")
        uac = ad.attr_int(u, "userAccountControl")
        groups = set(ad.attr_list(u, "memberOf"))
        is_disabled = bool(uac & UAC_DISABLED)
        in_priv_grp = bool(groups & priv_groups)
        if is_disabled:
            disabled_admins.append(name)
        else:
            llt = _ldap_ts_to_dt(_attr_raw(u, "lastLogonTimestamp"))
            days = _days_since(llt)
            if days is not None and days > 180:
                stale_admins.append(f"{name} (last logon: {days}d ago)")
            if not in_priv_grp and name.lower() not in (
                "administrator",
                "administrateur",
            ):
                orphan_admins.append(name)
    stats["admincount1_disabled"] = len(disabled_admins)
    stats["admincount1_stale"] = len(stale_admins)
    stats["admincount1_orphaned"] = len(orphan_admins)
    findings.append(
        F(
            "Privileged Accounts",
            f"adminCount=1 Account Inventory ({len(admin_count_users)} total)",
            "INFO",
            f"{len(admin_count_users)} user account(s) carry the adminCount=1 flag. "
            f"Breakdown: {len(disabled_admins)} disabled (ghost), "
            f"{len(orphan_admins)} orphaned, {len(stale_admins)} stale.",
            risk_score=0,
        )
    )
    if len(admin_count_users) > 20:
        findings.append(
            F(
                "Privileged Accounts",
                "Excessive adminCount=1 Accounts",
                "MEDIUM",
                f"{len(admin_count_users)} user account(s) have adminCount=1.",
                recommendation="Audit adminCount=1 accounts. Clear flag on accounts no longer in privileged groups.",
                risk_score=5,
            )
        )
    if disabled_admins:
        findings.append(
            F(
                "Privileged Accounts",
                "Disabled Accounts Retaining adminCount=1 (Ghost Admins)",
                "MEDIUM",
                f"{len(disabled_admins)} disabled account(s) still carry adminCount=1.",
                details=disabled_admins[:30],
                recommendation="Remove from all privileged groups and clear adminCount, then delete.",
                risk_score=8,
            )
        )
    if orphan_admins:
        findings.append(
            F(
                "Privileged Accounts",
                "Accounts with adminCount=1 but No Privileged Group Membership",
                "HIGH",
                f"{len(orphan_admins)} enabled account(s) have adminCount=1 but are not currently "
                "members of any known privileged group. Possible SDProp artefacts or backdoor accounts.",
                details=orphan_admins[:30],
                recommendation="Investigate each account. Clear adminCount and audit for backdoor ACEs.",
                risk_score=15,
            )
        )
    if stale_admins:
        findings.append(
            F(
                "Privileged Accounts",
                "Stale Accounts with adminCount=1 (Inactive 180+ Days)",
                "HIGH",
                f"{len(stale_admins)} admin account(s) have not logged in for 180+ days.",
                details=stale_admins[:30],
                recommendation="Disable inactive privileged accounts after 30-90 days of inactivity.",
                risk_score=12,
            )
        )
    return findings, stats


# -- 24. Passwords in User Descriptions ----------------------------------------


def check_passwords_in_descriptions(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Passwords in Descriptions")
    PASSWORD_KEYWORDS = (
        "password",
        "passwd",
        "pwd",
        "pass=",
        "pass:",
        "mot de passe",
        "kennwort",
        "contrasena",
        "wachtwoord",
        "parola",
        "senha",
        "secret",
        "credential",
        "p@ss",
        "p4ss",
    )
    users = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(description=*))",
        ["sAMAccountName", "description", "adminCount"],
    )
    computers = ad.search(
        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(description=*))",
        ["sAMAccountName", "description"],
    )
    user_hits, admin_hits, computer_hits = [], [], []
    for u in users:
        desc = ad.attr_str(u, "description").lower()
        if any(kw in desc for kw in PASSWORD_KEYWORDS):
            name = ad.attr_str(u, "sAMAccountName")
            is_adm = ad.attr_int(u, "adminCount") == 1
            entry = f"{name} -- \"{ad.attr_str(u,'description')[:80]}\""
            if is_adm:
                admin_hits.append(entry)
            else:
                user_hits.append(entry)
    for c in computers:
        desc = ad.attr_str(c, "description").lower()
        if any(kw in desc for kw in PASSWORD_KEYWORDS):
            name = ad.attr_str(c, "sAMAccountName")
            computer_hits.append(f"{name} -- \"{ad.attr_str(c,'description')[:80]}\"")
    stats["passwords_in_descriptions_admins"] = len(admin_hits)
    stats["passwords_in_descriptions_users"] = len(user_hits)
    stats["passwords_in_descriptions_computers"] = len(computer_hits)
    if admin_hits:
        findings.append(
            F(
                "Account Hygiene",
                "Privileged Accounts with Possible Password in Description",
                "CRITICAL",
                f"{len(admin_hits)} admin account(s) may have credentials in their Description field.",
                details=admin_hits[:30],
                recommendation="Immediately clear the Description field and rotate any exposed credentials.",
                risk_score=25,
            )
        )
    else:
        findings.append(
            F(
                "Account Hygiene",
                "No Passwords Found in Admin Account Descriptions",
                "INFO",
                "No privileged accounts have password-related keywords in their Description.",
                risk_score=0,
            )
        )
    if user_hits:
        findings.append(
            F(
                "Account Hygiene",
                "User Accounts with Possible Password in Description",
                "HIGH",
                f"{len(user_hits)} enabled user account(s) may have credentials in their Description.",
                details=user_hits[:30],
                recommendation="Clear the Description field and store credentials in a PAM vault.",
                risk_score=15,
            )
        )
    if computer_hits:
        findings.append(
            F(
                "Account Hygiene",
                "Computer Accounts with Possible Password in Description",
                "MEDIUM",
                f"{len(computer_hits)} computer account(s) may have credentials in their Description.",
                details=computer_hits[:20],
                recommendation="Clear the Description field on affected computer accounts.",
                risk_score=8,
            )
        )
    return findings, stats


# ══════════════════════════════════════════════════════════════════════════════
# NEW CHECKS 25–35
# ══════════════════════════════════════════════════════════════════════════════

# -- 25. GPP / cpassword (MS14-025) --------------------------------------------


def _decrypt_cpassword(cpassword: str) -> str:
    """
    Decrypt a Group Policy Preferences cpassword using Microsoft's
    publicly published AES-256 key (MS14-025).
    Requires pycryptodome (already in requirements.txt).
    """
    try:
        from Crypto.Cipher import AES
        import base64

        # AES-256 key published by Microsoft in MSDN (MS14-025)
        KEY = bytes(
            [
                0x4E,
                0x99,
                0x06,
                0xE8,
                0xFC,
                0xB6,
                0x6C,
                0xC9,
                0xFA,
                0xF4,
                0x93,
                0x10,
                0x62,
                0x0F,
                0xFE,
                0xE8,
                0xF4,
                0x96,
                0xE8,
                0x06,
                0xCC,
                0x05,
                0x79,
                0x90,
                0x20,
                0x9B,
                0x09,
                0xA4,
                0x33,
                0xB6,
                0x6C,
                0x83,
            ]
        )
        # Base64 padding
        pad = len(cpassword) % 4
        if pad:
            cpassword += "=" * (4 - pad)
        raw = base64.b64decode(cpassword)
        iv = b"\x00" * 16
        decrypted = AES.new(KEY, AES.MODE_CBC, iv).decrypt(raw)
        # Strip PKCS7 padding
        pad_len = decrypted[-1] if decrypted else 0
        return decrypted[:-pad_len].decode("utf-16-le", errors="ignore").strip()
    except ImportError:
        return "<pycryptodome not installed>"
    except Exception as e:
        return f"<decryption failed: {e}>"


def _scan_sysvol_for_gpp(dc_ip: str, domain: str) -> Any:
    """
    Walk SYSVOL via UNC path (Windows) or local mount (Linux/macOS if Samba-mounted)
    and return a list of (file_path, username, decrypted_password) or None if unreachable.
    """
    GPP_FILES = {
        "Groups.xml",
        "Services.xml",
        "Scheduledtasks.xml",
        "DataSources.xml",
        "Printers.xml",
        "Drives.xml",
    }
    sysvol_path = f"\\\\{dc_ip}\\SYSVOL\\{domain}\\Policies"
    # On Linux try /mnt/sysvol or common Samba mount points
    if not os.path.exists(sysvol_path):
        for alt in (f"/mnt/sysvol/{domain}/Policies", f"/tmp/sysvol/{domain}/Policies"):
            if os.path.exists(alt):
                sysvol_path = alt
                break
        else:
            return None  # SYSVOL not accessible

    hits = []
    try:
        for root_dir, _, files in os.walk(sysvol_path):
            for fname in files:
                if fname not in GPP_FILES:
                    continue
                fpath = os.path.join(root_dir, fname)
                try:
                    tree = ET.parse(fpath)
                    for elem in tree.iter():
                        cpassword = elem.get("cpassword", "")
                        if not cpassword:
                            continue
                        username = (
                            elem.get("userName")
                            or elem.get("runAs")
                            or elem.get("username")
                            or "<unknown>"
                        )
                        decrypted = _decrypt_cpassword(cpassword)
                        hits.append((fpath, username, decrypted))
                except Exception:
                    continue
    except PermissionError:
        return None
    except Exception:
        return None

    return hits


def check_gpp_passwords(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] GPP / cpassword in SYSVOL (MS14-025)")

    result = _scan_sysvol_for_gpp(ad.dc_ip, ad.domain)

    if result is None:
        stats["gpp_sysvol_accessible"] = False
        findings.append(
            F(
                "GPP Passwords",
                "SYSVOL Not Accessible -- GPP Scan Skipped",
                "INFO",
                f"Could not walk \\\\{ad.dc_ip}\\SYSVOL. "
                "Run from a domain-joined Windows host, or mount SYSVOL via Samba and re-run. "
                "Manual check: findstr /S /I cpassword \\\\{domain}\\sysvol\\**\\*.xml",
                recommendation="Search SYSVOL manually for cpassword attributes in GPP XML files.",
                risk_score=0,
                references=["https://attack.mitre.org/techniques/T1552/006/"],
            )
        )
        return findings, stats

    stats["gpp_sysvol_accessible"] = True
    stats["gpp_cpassword_count"] = len(result)

    if result:
        details = []
        for fpath, username, decrypted in result:
            tail = fpath[-80:] if len(fpath) > 80 else fpath
            details.append(f"user={username}  file=...{tail}  password={decrypted}")
        findings.append(
            F(
                "GPP Passwords",
                "Plaintext Credentials Found in SYSVOL GPP (MS14-025)",
                "CRITICAL",
                f"{len(result)} cpassword attribute(s) found in Group Policy Preferences XML files. "
                "These are encrypted with a static AES key published by Microsoft -- "
                "the plaintext passwords above are readable by any domain user.",
                details=details,
                recommendation=(
                    "Delete all GPP preferences that store passwords. "
                    "Use LAPS or a PAM vault for local admin credentials. "
                    "Apply patch KB2962486 (MS14-025)."
                ),
                risk_score=25,
                references=[
                    "https://attack.mitre.org/techniques/T1552/006/",
                    "https://support.microsoft.com/kb/2962486",
                ],
            )
        )
    else:
        findings.append(
            F(
                "GPP Passwords",
                "No cpassword Attributes Found in SYSVOL",
                "INFO",
                "SYSVOL was accessible and no GPP cpassword attributes were detected.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 26. AdminSDHolder ACL Inspection ------------------------------------------


def check_adminsdholder(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] AdminSDHolder ACL")

    from ldap3 import BASE
    from ldap3.protocol.microsoft import security_descriptor_control

    adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{ad.base_dn}"
    domain_sid = _get_domain_sid(ad)
    risky_aces = []

    try:
        ctrl = security_descriptor_control(sdflags=0x04)
        ad.conn.search(
            search_base=adminsdholder_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["nTSecurityDescriptor"],
            controls=ctrl,
        )
        if not ad.conn.entries:
            findings.append(
                F(
                    "AdminSDHolder",
                    "AdminSDHolder Object Not Readable",
                    "INFO",
                    "Could not read AdminSDHolder ACL.",
                    risk_score=0,
                )
            )
            return findings, stats

        sd_attr = getattr(ad.conn.entries[0], "nTSecurityDescriptor", None)
        raw_sd = sd_attr.raw_values[0] if (sd_attr and sd_attr.raw_values) else None
        if not raw_sd:
            return findings, stats

        for ace in _parse_sd(raw_sd):
            if ace["ace_type"] not in (0x00, 0x05):
                continue
            sid = ace["trustee_sid"]
            mask = ace["access_mask"]
            if _sid_is_privileged(sid, domain_sid):
                continue
            if mask & (
                AM_GENERIC_ALL
                | AM_WRITE_DACL
                | AM_WRITE_OWNER
                | AM_GENERIC_WRITE
                | AM_WRITE_PROP
            ):
                risky_aces.append(f"{ad.resolve_sid(sid)} -- mask: 0x{mask:08x}")

    except Exception as e:
        print(f"  [~] AdminSDHolder ACL read failed: {e}")
        return findings, stats

    stats["adminsdholder_risky_aces"] = len(risky_aces)

    if risky_aces:
        findings.append(
            F(
                "AdminSDHolder",
                "Unexpected Write ACEs on AdminSDHolder (SDProp Persistence)",
                "CRITICAL",
                f"{len(risky_aces)} non-privileged principal(s) have write permissions on AdminSDHolder. "
                "SDProp propagates these ACEs to ALL protected group members every 60 minutes, "
                "granting persistent, auto-restoring domain privilege that survives most cleanup.",
                details=risky_aces,
                recommendation=(
                    "Remove all unexpected ACEs from AdminSDHolder immediately: "
                    "(Get-Acl 'AD:CN=AdminSDHolder,CN=System,...').Access | "
                    "Where-Object {<non-admin filter>} | ForEach {Remove-AdPermission ...}"
                ),
                risk_score=25,
                references=[
                    "https://attack.mitre.org/techniques/T1078/002/",
                    "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
                ],
            )
        )
    else:
        findings.append(
            F(
                "AdminSDHolder",
                "AdminSDHolder ACL -- No Unexpected Permissions",
                "INFO",
                "No non-privileged principals have write access to AdminSDHolder.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 27. SID History Abuse -----------------------------------------------------


def check_sid_history(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] SID History")

    domain_sid = _get_domain_sid(ad)

    results = ad.search(
        "(&(objectClass=user)(sIDHistory=*))",
        ["sAMAccountName", "sIDHistory", "userAccountControl", "adminCount"],
    )
    results += ad.search(
        "(&(objectClass=computer)(sIDHistory=*))",
        ["sAMAccountName", "sIDHistory", "userAccountControl"],
    )

    stats["sid_history_count"] = len(results)

    if not results:
        findings.append(
            F(
                "SID History",
                "No Accounts with SID History",
                "INFO",
                "No user or computer accounts have the sIDHistory attribute populated.",
                risk_score=0,
            )
        )
        return findings, stats

    priv_hits, normal_hits = [], []
    for u in results:
        name = ad.attr_str(u, "sAMAccountName")
        sids = ad.attr_list(u, "sIDHistory")
        for sid_val in sids:
            sid_str = str(sid_val)
            if _sid_is_privileged(sid_str, domain_sid):
                priv_hits.append(f"{name} -> {sid_str} [PRIVILEGED SID]")
            else:
                normal_hits.append(f"{name} -> {sid_str}")

    if priv_hits:
        findings.append(
            F(
                "SID History",
                "Accounts with Privileged SIDs in sIDHistory (Backdoor Detected)",
                "CRITICAL",
                f"{len(priv_hits)} account(s) carry privileged domain SIDs in sIDHistory. "
                "These accounts effectively hold the privileges of the injected SID without "
                "appearing in any privileged group -- a common post-compromise persistence technique.",
                details=priv_hits,
                recommendation=(
                    "Immediately investigate and clear sIDHistory: "
                    "Set-ADUser <user> -Remove @{sIDHistory='<SID>'}. "
                    "Enable SID filtering on all trusts to prevent cross-domain exploitation."
                ),
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1134/005/"],
            )
        )

    if normal_hits:
        sev = "LOW" if not priv_hits else "INFO"
        findings.append(
            F(
                "SID History",
                "Accounts with Non-Privileged SID History Entries",
                sev,
                f"{len(normal_hits)} account(s) have non-privileged SID history entries. "
                "These may be legitimate migration artefacts or incomplete cleanup after an attack.",
                details=normal_hits[:20],
                recommendation=(
                    "Review all SID history entries. Clear sIDHistory once migrations are complete. "
                    "Enable SID filtering on all domain trusts."
                ),
                risk_score=3 if not priv_hits else 0,
                references=["https://attack.mitre.org/techniques/T1134/005/"],
            )
        )

    return findings, stats


# -- 28. Shadow Credentials (msDS-KeyCredentialLink) ---------------------------


def check_shadow_credentials(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Shadow Credentials (msDS-KeyCredentialLink)")

    users = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))(msDS-KeyCredentialLink=*))",
        [
            "sAMAccountName",
            "msDS-KeyCredentialLink",
            "adminCount",
            "userAccountControl",
        ],
    )
    computers = ad.search(
        "(&(objectClass=computer)(msDS-KeyCredentialLink=*))",
        ["sAMAccountName", "msDS-KeyCredentialLink", "userAccountControl"],
    )

    total = len(users) + len(computers)
    stats["shadow_credentials_count"] = total

    if not total:
        findings.append(
            F(
                "Shadow Credentials",
                "No Unexpected msDS-KeyCredentialLink Entries Detected",
                "INFO",
                "No user or computer accounts have msDS-KeyCredentialLink set "
                "(or entries are only on DCs as expected for Windows Hello for Business).",
                risk_score=0,
            )
        )
        return findings, stats

    admin_hits, user_hits, comp_hits = [], [], []

    for u in users:
        name = ad.attr_str(u, "sAMAccountName")
        count = len(ad.attr_list(u, "msDS-KeyCredentialLink"))
        is_adm = ad.attr_int(u, "adminCount") == 1
        entry = f"{name} ({count} key credential(s))"
        if is_adm:
            admin_hits.append(entry)
        else:
            user_hits.append(entry)

    for c in computers:
        name = ad.attr_str(c, "sAMAccountName")
        count = len(ad.attr_list(c, "msDS-KeyCredentialLink"))
        comp_hits.append(f"{name} ({count} key credential(s))")

    if admin_hits:
        findings.append(
            F(
                "Shadow Credentials",
                "Admin Accounts with msDS-KeyCredentialLink Set (Shadow Credentials)",
                "CRITICAL",
                f"{len(admin_hits)} privileged account(s) have shadow credentials. "
                "An attacker who set these entries can authenticate as the account via PKINIT "
                "certificate-based auth WITHOUT knowing the password, providing covert persistence.",
                details=admin_hits,
                recommendation=(
                    "Clear msDS-KeyCredentialLink from all accounts unless Windows Hello for Business "
                    "is deployed and managed: Set-ADUser <user> -Clear msDS-KeyCredentialLink. "
                    "Review the change log to identify who added these entries."
                ),
                risk_score=25,
                references=[
                    "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"
                ],
            )
        )

    if user_hits or comp_hits:
        all_hits = user_hits + comp_hits
        sev = "HIGH" if not admin_hits else "MEDIUM"
        findings.append(
            F(
                "Shadow Credentials",
                "Non-Admin Accounts with msDS-KeyCredentialLink Set",
                sev,
                f"{len(all_hits)} non-admin account(s) or computer(s) have shadow credentials set. "
                "Verify these are legitimate Windows Hello for Business device registrations.",
                details=all_hits[:25],
                recommendation=(
                    "Audit all msDS-KeyCredentialLink entries. Clear unexpected ones. "
                    "If WHfB is not deployed, all entries are suspicious."
                ),
                risk_score=15 if sev == "HIGH" else 5,
                references=[
                    "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"
                ],
            )
        )

    return findings, stats


# -- 29. RC4 / Legacy Kerberos Encryption --------------------------------------


def check_rc4_encryption(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] RC4 / Legacy Kerberos Encryption")

    # msDS-SupportedEncryptionTypes bit flags
    # 0x01=DES-CBC-CRC  0x02=DES-CBC-MD5  0x04=RC4-HMAC  0x08=AES128  0x10=AES256
    RC4_BIT = 0x04
    AES_BITS = 0x18  # AES128 | AES256

    # Service accounts (with SPNs) that support RC4
    svc_accs = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "msDS-SupportedEncryptionTypes", "adminCount"],
    )
    # Domain controllers
    dcs = ad.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "dNSHostName", "msDS-SupportedEncryptionTypes"],
    )
    # Privileged users without AES-only config
    admin_users = ad.search(
        "(&(objectClass=user)(!(objectClass=computer))(adminCount=1)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "msDS-SupportedEncryptionTypes"],
    )

    svc_rc4_hits, dc_rc4_hits, admin_noaes_hits = [], [], []

    for u in svc_accs:
        enc = ad.attr_int(u, "msDS-SupportedEncryptionTypes")
        # enc == 0 means default (includes RC4); explicit check if RC4 bit set
        if enc == 0 or (enc & RC4_BIT):
            name = ad.attr_str(u, "sAMAccountName")
            tag = " [ADMIN]" if ad.attr_int(u, "adminCount") == 1 else ""
            svc_rc4_hits.append(f"{name}{tag} (encTypes=0x{enc:x})")

    for dc in dcs:
        enc = ad.attr_int(dc, "msDS-SupportedEncryptionTypes")
        name = ad.attr_str(dc, "dNSHostName") or ad.attr_str(dc, "sAMAccountName")
        if enc == 0 or (enc & RC4_BIT):
            dc_rc4_hits.append(f"{name} (encTypes=0x{enc:x})")

    for u in admin_users:
        enc = ad.attr_int(u, "msDS-SupportedEncryptionTypes")
        if enc != 0 and not (enc & AES_BITS):  # Explicitly configured without AES
            admin_noaes_hits.append(
                f"{ad.attr_str(u,'sAMAccountName')} (encTypes=0x{enc:x})"
            )

    stats["rc4_service_accounts"] = len(svc_rc4_hits)
    stats["rc4_domain_controllers"] = len(dc_rc4_hits)
    stats["admin_no_aes_encryption"] = len(admin_noaes_hits)

    if svc_rc4_hits:
        sev = "CRITICAL" if any("[ADMIN]" in h for h in svc_rc4_hits) else "HIGH"
        findings.append(
            F(
                "Kerberos Encryption",
                "Service Accounts Permitting RC4 Kerberos Encryption",
                sev,
                f"{len(svc_rc4_hits)} service account(s) with SPNs accept RC4-HMAC Kerberos tickets. "
                "Attackers specifically request RC4 tickets even when AES is available, because "
                "RC4 hashes crack orders of magnitude faster than AES hashes offline.",
                details=svc_rc4_hits[:30],
                recommendation=(
                    "Set msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256 only) on all service accounts: "
                    "Set-ADUser <account> -KerberosEncryptionType AES128,AES256"
                ),
                risk_score=20 if sev == "CRITICAL" else 12,
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )
        )

    if dc_rc4_hits:
        findings.append(
            F(
                "Kerberos Encryption",
                "Domain Controllers Permitting RC4 Kerberos Encryption",
                "MEDIUM",
                f"{len(dc_rc4_hits)} DC(s) have RC4 in their supported encryption types, "
                "allowing clients to negotiate weaker RC4 tickets.",
                details=dc_rc4_hits,
                recommendation=(
                    "Configure Network Security: Configure encryption types allowed for Kerberos "
                    "via GPO to require AES only. Disable RC4 compatibility once all clients support AES."
                ),
                risk_score=8,
            )
        )

    if admin_noaes_hits:
        findings.append(
            F(
                "Kerberos Encryption",
                "Admin Accounts Explicitly Configured Without AES Kerberos Support",
                "HIGH",
                f"{len(admin_noaes_hits)} privileged account(s) have msDS-SupportedEncryptionTypes "
                "set without any AES bits, forcing legacy encryption for admin sessions.",
                details=admin_noaes_hits,
                recommendation="Set AES128+AES256 encryption types on all admin accounts.",
                risk_score=12,
            )
        )

    if not svc_rc4_hits and not dc_rc4_hits and not admin_noaes_hits:
        findings.append(
            F(
                "Kerberos Encryption",
                "No RC4-Only Kerberos Configurations Detected",
                "INFO",
                "All checked accounts and DCs appear to support AES Kerberos encryption.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 30. Foreign Security Principals in Privileged Groups ----------------------


def check_foreign_security_principals(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Foreign Security Principals in Privileged Groups")

    SENSITIVE_GROUPS = {
        "Domain Admins": f"CN=Domain Admins,CN=Users,{ad.base_dn}",
        "Enterprise Admins": f"CN=Enterprise Admins,CN=Users,{ad.base_dn}",
        "Schema Admins": f"CN=Schema Admins,CN=Users,{ad.base_dn}",
        "Administrators": f"CN=Administrators,CN=Builtin,{ad.base_dn}",
        "Account Operators": f"CN=Account Operators,CN=Builtin,{ad.base_dn}",
        "Backup Operators": f"CN=Backup Operators,CN=Builtin,{ad.base_dn}",
        "Server Operators": f"CN=Server Operators,CN=Builtin,{ad.base_dn}",
        "Group Policy Creator Owners": f"CN=Group Policy Creator Owners,CN=Users,{ad.base_dn}",
    }

    fsp_base = f"CN=ForeignSecurityPrincipals,{ad.base_dn}"
    fsps = ad.search(
        "(objectClass=foreignSecurityPrincipal)", ["cn", "memberOf"], base=fsp_base
    )

    hits = []
    for fsp in fsps:
        sid = ad.attr_str(fsp, "cn")
        groups = ad.attr_list(fsp, "memberOf")
        for gdn in groups:
            for gname, sensitive_dn in SENSITIVE_GROUPS.items():
                if gdn.lower() == sensitive_dn.lower():
                    resolved = ad.resolve_sid(sid)
                    hits.append(f"{resolved} (SID: {sid}) -> {gname}")

    stats["foreign_security_principals_in_priv_groups"] = len(hits)

    if hits:
        findings.append(
            F(
                "Foreign Security Principals",
                "Foreign Security Principals in Privileged Groups",
                "CRITICAL",
                f"{len(hits)} FSP(s) from trusted domains are members of sensitive local groups. "
                "Compromising the source domain or trust grants immediate privilege in this domain.",
                details=hits,
                recommendation=(
                    "Remove FSPs from all privileged groups unless there is an explicit, "
                    "documented business requirement. Consider enabling selective authentication "
                    "on trusts to limit cross-domain access."
                ),
                risk_score=20,
                references=["https://attack.mitre.org/techniques/T1484/002/"],
            )
        )
    else:
        findings.append(
            F(
                "Foreign Security Principals",
                "No Foreign Security Principals in Privileged Groups",
                "INFO",
                "No FSPs from trusted domains were found in sensitive groups.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 31. Pre-Windows 2000 Compatible Access Group ------------------------------


def check_pre_windows_2000(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Pre-Windows 2000 Compatible Access Group")

    pre2k_dn = f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{ad.base_dn}"
    grp = ad.search(f"(distinguishedName={pre2k_dn})", ["member"])

    if not grp:
        findings.append(
            F(
                "Pre-Win2k Access",
                "Pre-Windows 2000 Group Not Found",
                "INFO",
                "Could not locate the Pre-Windows 2000 Compatible Access group.",
                risk_score=0,
            )
        )
        return findings, stats

    members = ad.attr_list(grp[0], "member")
    everyone = any(_EVERYONE in m or "S-1-1-0" in m for m in members)
    anon = any(_ANON in m or "S-1-5-7" in m for m in members)
    auth = any(_AUTH_USERS in m or "S-1-5-11" in m for m in members)

    stats["pre_win2k_members"] = len(members)
    stats["pre_win2k_everyone"] = everyone
    stats["pre_win2k_anon"] = anon

    if everyone or anon:
        sev = "CRITICAL"
        who = []
        if everyone:
            who.append("Everyone (S-1-1-0)")
        if anon:
            who.append("Anonymous Logon (S-1-5-7)")
        findings.append(
            F(
                "Pre-Win2k Access",
                "Pre-Windows 2000 Group Grants Unauthenticated Enumeration",
                sev,
                f"The Pre-Windows 2000 Compatible Access group contains {', '.join(who)}. "
                "Any unauthenticated attacker on the network can enumerate users, groups, "
                "and password policies via legacy SAMR/LSARPC protocols.",
                details=who,
                recommendation=(
                    "Remove Everyone and Anonymous Logon from this group immediately: "
                    "net localgroup 'Pre-Windows 2000 Compatible Access' Everyone /delete. "
                    "Verify no legacy applications depend on anonymous SAMR access."
                ),
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1087/002/"],
            )
        )
    elif auth:
        findings.append(
            F(
                "Pre-Win2k Access",
                "Pre-Windows 2000 Group Contains Authenticated Users",
                "MEDIUM",
                "Authenticated Users in this group broadens SAMR enumeration rights beyond "
                "what modern AD requires.",
                recommendation=(
                    "Remove Authenticated Users unless a specific legacy application requires it. "
                    "Restrict SAMR enumeration via GPO: "
                    "Network access: Restrict clients allowed to make remote calls to SAM."
                ),
                risk_score=8,
            )
        )
    elif members:
        findings.append(
            F(
                "Pre-Win2k Access",
                "Pre-Windows 2000 Group Has Non-Standard Members",
                "LOW",
                f"{len(members)} member(s) found. Verify each is required.",
                details=members[:20],
                recommendation="Remove all members unless required by legacy applications.",
                risk_score=3,
            )
        )
    else:
        findings.append(
            F(
                "Pre-Win2k Access",
                "Pre-Windows 2000 Compatible Access Group Is Empty",
                "INFO",
                "No members found -- good.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 32. Dangerous Constrained Delegation Targets ------------------------------


def check_dangerous_delegation_targets(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Dangerous Constrained Delegation Targets")

    # Collect all DC hostnames for comparison
    dcs = ad.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["dNSHostName", "sAMAccountName"],
    )
    dc_names = set()
    for dc in dcs:
        h = ad.attr_str(dc, "dNSHostName").lower()
        s = ad.attr_str(dc, "sAMAccountName").lower().rstrip("$")
        if h:
            dc_names.add(h)
        if s:
            dc_names.add(s)

    delegating = ad.search(
        "(msDS-AllowedToDelegateTo=*)",
        ["sAMAccountName", "msDS-AllowedToDelegateTo", "objectClass", "adminCount"],
    )

    high_value_hits = []

    for obj in delegating:
        name = ad.attr_str(obj, "sAMAccountName")
        targets = ad.attr_list(obj, "msDS-AllowedToDelegateTo")
        for tgt in targets:
            tgt_lower = tgt.lower()
            # Check if SPN prefix is sensitive
            svc_prefix = tgt_lower.split("/")[0] + "/" if "/" in tgt_lower else ""
            host_part = (
                tgt_lower.split("/")[1].split(":")[0].split(".")[0]
                if "/" in tgt_lower
                else ""
            )
            is_dangerous_svc = any(
                tgt_lower.startswith(p) for p in DANGEROUS_SVC_PREFIXES
            )
            is_dc_target = host_part in dc_names
            is_admin = ad.attr_int(obj, "adminCount") == 1
            if is_dangerous_svc and is_dc_target:
                tag = " [ADMIN-SOURCE]" if is_admin else ""
                high_value_hits.append(
                    f"{name}{tag} -> {tgt}  [DC target + sensitive SPN]"
                )

    stats["dangerous_delegation_targets"] = len(high_value_hits)

    if high_value_hits:
        findings.append(
            F(
                "Delegation",
                "Constrained Delegation to High-Value Services on Domain Controllers",
                "CRITICAL",
                f"{len(high_value_hits)} account(s) are configured to delegate to sensitive services "
                f"(ldap, cifs, host, gc, krbtgt) on Domain Controllers. "
                "An attacker who compromises these accounts can impersonate any domain user "
                "to the DC's most privileged interfaces, effectively achieving DA.",
                details=high_value_hits,
                recommendation=(
                    "Remove delegation to LDAP, CIFS, HOST, GC, and KRBTGT on DCs unless absolutely required. "
                    "If required, restrict via 'Users or computers that are trusted for delegation' "
                    "and enable 'Require Kerberos' (no protocol transition). "
                    "Prefer RBCD with minimal target scope."
                ),
                risk_score=25,
                references=[
                    "https://attack.mitre.org/techniques/T1134/001/",
                    "https://blog.harmj0y.net/activedirectory/s4u2abuse/",
                ],
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No Dangerous Constrained Delegation Targets Detected",
                "INFO",
                "No accounts delegate to sensitive services (ldap/cifs/host/gc) on Domain Controllers.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 33. Orphaned AD Subnets ---------------------------------------------------


def check_orphaned_subnets(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] Orphaned AD Subnets")

    subnets = ad.search(
        "(objectClass=subnet)",
        ["cn", "siteObject", "description"],
        base=f"CN=Subnets,CN=Sites,{ad.config_dn}",
    )

    orphaned = []
    all_subs = []
    for s in subnets:
        cidr = ad.attr_str(s, "cn")
        site_obj = ad.attr_str(s, "siteObject")
        all_subs.append(cidr)
        if not site_obj:
            orphaned.append(cidr)

    stats["subnet_count"] = len(subnets)
    stats["orphaned_subnet_count"] = len(orphaned)

    if orphaned:
        findings.append(
            F(
                "Site Topology",
                "AD Subnets Not Associated with Any Site",
                "LOW",
                f"{len(orphaned)} of {len(subnets)} subnet(s) have no site assignment. "
                "Clients from these subnets will receive a suboptimal (random) DC, "
                "causing authentication traffic to traverse WAN links unnecessarily. "
                "In multi-site environments this can also expose credentials to less-secure links.",
                details=orphaned[:30],
                recommendation=(
                    "Assign each subnet to the appropriate AD site: "
                    "New-ADReplicationSubnet -Name <CIDR> -Site <SiteName> "
                    "or via Active Directory Sites and Services MMC."
                ),
                risk_score=3,
            )
        )
    else:
        findings.append(
            F(
                "Site Topology",
                "All AD Subnets Are Assigned to a Site",
                "INFO",
                f"All {len(subnets)} subnet(s) are correctly mapped to AD sites.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 34. Legacy FRS SYSVOL Replication -----------------------------------------


def check_frs_replication(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] SYSVOL Replication (FRS vs DFSR)")

    # nTFRSSubscriber objects exist only if FRS is still configured
    frs_subs = ad.search("(objectClass=nTFRSSubscriber)", ["cn", "distinguishedName"])

    # Check DFSR migration state on the domain object
    dom = ad.get_domain_object()
    dfsr_state = None
    if dom:
        # msDFSR-Flags on the SYSVOL subscription indicates migration status
        # State 0/None = FRS, State 3 = DFSR eliminated
        dfsr_state = ad.attr_int(dom, "msDFSR-Flags", default=-1)

    # Also look for DFSR subscription objects as confirmation DFSR is running
    dfsr_subs = ad.search(
        "(objectClass=msDFSR-Subscription)",
        ["cn"],
        base=f"CN=DFSR-GlobalSettings,CN=System,{ad.base_dn}",
    )

    using_frs = bool(frs_subs) and not bool(dfsr_subs)
    mixed_mode = bool(frs_subs) and bool(dfsr_subs)

    stats["frs_subscriber_count"] = len(frs_subs)
    stats["dfsr_subscriber_count"] = len(dfsr_subs)
    stats["sysvol_using_frs"] = using_frs

    if using_frs:
        findings.append(
            F(
                "SYSVOL Replication",
                "SYSVOL Still Replicating via Legacy FRS (File Replication Service)",
                "HIGH",
                "FRS was deprecated in Windows Server 2008 R2 and is no longer supported. "
                "FRS replication is unreliable and cannot be monitored with modern tools. "
                "It also blocks raising the domain functional level above 2003.",
                recommendation=(
                    "Migrate SYSVOL replication from FRS to DFSR using the dfsrmig tool: "
                    "dfsrmig /SetGlobalState 3  (four-phase migration). "
                    "Reference: https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"
                ),
                risk_score=12,
                references=[
                    "https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr",
                ],
            )
        )
    elif mixed_mode:
        findings.append(
            F(
                "SYSVOL Replication",
                "SYSVOL Migration to DFSR Appears Incomplete",
                "MEDIUM",
                "Both FRS subscriber objects and DFSR subscription objects exist. "
                "The SYSVOL migration may be stalled mid-phase.",
                recommendation=(
                    "Check migration state: dfsrmig /GetGlobalState. "
                    "Complete the migration to state 3 (Eliminated)."
                ),
                risk_score=5,
            )
        )
    else:
        findings.append(
            F(
                "SYSVOL Replication",
                "SYSVOL Replication Uses DFSR (Modern)",
                "INFO",
                "No legacy FRS subscriber objects detected. DFSR is in use.",
                risk_score=0,
            )
        )

    return findings, stats


# -- 35. RBCD on Domain Object Itself ------------------------------------------


def check_rbcd_on_domain(ad: ADConnector) -> Tuple[List[F], Dict]:
    findings, stats = [], {}
    print("  [*] RBCD on Domain Object")

    from ldap3 import BASE
    from ldap3.protocol.microsoft import security_descriptor_control

    domain_sid = _get_domain_sid(ad)

    # Check msDS-AllowedToActOnBehalfOfOtherIdentity on the domain NC head
    dom_results = ad.search(
        "(objectClass=domain)",
        ["msDS-AllowedToActOnBehalfOfOtherIdentity", "distinguishedName"],
        base=ad.base_dn,
    )

    rbcd_on_domain = False
    raw_rbcd = None
    if dom_results:
        raw_attr = getattr(
            dom_results[0], "msDS-AllowedToActOnBehalfOfOtherIdentity", None
        )
        if raw_attr and raw_attr.value:
            rbcd_on_domain = True
            if hasattr(raw_attr, "raw_values") and raw_attr.raw_values:
                raw_rbcd = raw_attr.raw_values[0]

    stats["rbcd_on_domain_object"] = rbcd_on_domain

    if rbcd_on_domain:
        # Parse the security descriptor to find who can delegate
        trustees = []
        if raw_rbcd:
            for ace in _parse_sd(raw_rbcd):
                if ace["ace_type"] == 0x00:  # ACCESS_ALLOWED_ACE
                    trustees.append(ad.resolve_sid(ace["trustee_sid"]))

        findings.append(
            F(
                "Delegation",
                "RBCD Configured on Domain Object -- Full Domain Compromise Path",
                "CRITICAL",
                "msDS-AllowedToActOnBehalfOfOtherIdentity is set on the domain NC head object. "
                "Any principal in this RBCD ACL can impersonate ANY domain user to ANY service "
                "in the domain, granting effective Domain Admin without being in any privileged group.",
                details=trustees if trustees else ["<trustees could not be parsed>"],
                recommendation=(
                    "Remove msDS-AllowedToActOnBehalfOfOtherIdentity from the domain object immediately: "
                    "Set-ADObject (Get-ADDomain).DistinguishedName "
                    "-Clear msDS-AllowedToActOnBehalfOfOtherIdentity"
                ),
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1134/001/"],
            )
        )
    else:
        findings.append(
            F(
                "Delegation",
                "No RBCD Configured on Domain Object",
                "INFO",
                "msDS-AllowedToActOnBehalfOfOtherIdentity is not set on the domain NC head.",
                risk_score=0,
            )
        )

    # Also check all DC computer objects for RBCD (separate from check 4's
    # generic RBCD scan -- this specifically flags DCs)
    dc_rbcd = ad.search(
        "(&(objectClass=computer)"
        "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        ["sAMAccountName", "dNSHostName"],
    )

    stats["rbcd_on_dc_count"] = len(dc_rbcd)

    if dc_rbcd:
        details = [
            ad.attr_str(dc, "dNSHostName") or ad.attr_str(dc, "sAMAccountName")
            for dc in dc_rbcd
        ]
        findings.append(
            F(
                "Delegation",
                "RBCD Configured Directly on Domain Controller Computer Objects",
                "CRITICAL",
                f"{len(dc_rbcd)} Domain Controller(s) have RBCD set. "
                "Any account in the RBCD ACL can impersonate any domain user to the DC, "
                "enabling full domain compromise via S4U2Proxy.",
                details=details,
                recommendation=(
                    "Remove msDS-AllowedToActOnBehalfOfOtherIdentity from all DC objects: "
                    "Get-ADComputer -Filter {PrimaryGroupID -eq 516} | "
                    "Set-ADComputer -Clear msDS-AllowedToActOnBehalfOfOtherIdentity"
                ),
                risk_score=25,
                references=["https://attack.mitre.org/techniques/T1134/001/"],
            )
        )

    return findings, stats


# ══════════════════════════════════════════════════════════════════════════════
# AGGREGATOR
# ══════════════════════════════════════════════════════════════════════════════


def run_all_checks(ad: ADConnector):
    all_findings = []
    all_stats: Dict[str, Any] = {}

    checks = [
        # Original 24
        check_password_policy,
        check_privileged_accounts,
        check_kerberos,
        check_unconstrained_delegation,
        check_constrained_delegation,
        check_adcs,
        check_trusts,
        check_account_hygiene,
        check_protocols,
        check_gpo,
        check_laps,
        check_laps_coverage,
        check_dns,
        check_domain_controllers,
        check_acls,
        check_optional_features,
        check_replication,
        check_service_accounts,
        check_misc,
        check_deprecated_os,
        check_legacy_protocols,
        check_exchange,
        check_admin_count,
        check_passwords_in_descriptions,
        # New 11
        check_gpp_passwords,
        check_adminsdholder,
        check_sid_history,
        check_shadow_credentials,
        check_rc4_encryption,
        check_foreign_security_principals,
        check_pre_windows_2000,
        check_dangerous_delegation_targets,
        check_orphaned_subnets,
        check_frs_replication,
        check_rbcd_on_domain,
    ]

    for fn in checks:
        try:
            f, s = fn(ad)
            all_findings.extend(f)
            all_stats.update(s)
        except Exception as ex:
            print(f"  [!] Check failed ({fn.__name__}): {ex}")

    return all_findings, all_stats
