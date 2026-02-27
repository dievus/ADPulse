"""
LDAP(S) connector with optional pass-the-hash authentication.

How PtH works here without impacket
────────────────────────────────────
ldap3's NTLM stack derives the NT hash by computing:
    NT_hash = MD4(password.encode('utf-16-le'))

For pass-the-hash we already *have* the NT hash and need to skip that step.
The _pth_context() context manager temporarily replaces hashlib.new('md4')
with a stub whose .digest() returns our pre-computed hash directly.
The patch is active only for the duration of the bind call, then immediately
restored — so it cannot bleed into search operations or other threads.
"""

import contextlib
import hashlib as _stdlib_hashlib
import ssl
import socket
from typing import Optional, List

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, ALL_ATTRIBUTES, Tls
from ldap3.core.exceptions import LDAPException

# ── Helpers ───────────────────────────────────────────────────────────────────

EMPTY_LM_HEX = "aad3b435b51404eeaad3b435b51404ee"


def resolve_dc(domain: str) -> Optional[str]:
    for name in (f"_ldap._tcp.dc._msdcs.{domain}", domain):
        try:
            return socket.gethostbyname(name)
        except Exception:
            continue
    return None


def parse_hash(hash_str: str):
    """
    Parse [LMHASH:]NTHASH and return (lm_bytes, nt_bytes).

    Accepted formats
    ----------------
    31d6cfe0d16ae931b73c59d7e0c089c0
    aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    :31d6cfe0d16ae931b73c59d7e0c089c0   (empty LM — colon still required)
    """
    parts = hash_str.strip().split(":")
    if len(parts) == 2:
        lm_hex, nt_hex = parts
    else:
        lm_hex, nt_hex = "", parts[0]

    lm_hex = lm_hex or EMPTY_LM_HEX

    try:
        lm_bytes = bytes.fromhex(lm_hex)
        nt_bytes = bytes.fromhex(nt_hex)
    except ValueError as exc:
        raise ValueError(
            f"Invalid hash format '{hash_str}'. "
            "Expected [LMHASH:]NTHASH as hex strings."
        ) from exc

    if len(nt_bytes) != 16:
        raise ValueError(f"NT hash must be 16 bytes (32 hex chars), got {len(nt_bytes)}.")

    return lm_bytes, nt_bytes


# ── Pass-the-hash context manager ─────────────────────────────────────────────

@contextlib.contextmanager
def _pth_context(nt_hash_bytes: bytes):
    """
    Temporarily replace hashlib.new('md4') so that ldap3's NTLM
    implementation uses our pre-computed NT hash instead of deriving
    one from a plaintext password.

    The replacement is active only while the `with` block is executing
    and is guaranteed to be removed even if an exception is raised.
    """
    _orig_new = _stdlib_hashlib.new

    class _FakeMD4:
        """Mimics a hashlib hash object; digest() always returns our hash."""
        def __init__(self):
            self._data = b""

        def update(self, data: bytes) -> None:
            # Accept (and ignore) data — we always return the injected hash.
            self._data += data

        def digest(self) -> bytes:
            return nt_hash_bytes

        def hexdigest(self) -> str:
            return nt_hash_bytes.hex()

        def copy(self) -> "_FakeMD4":
            c = _FakeMD4()
            c._data = self._data
            return c

    def _patched_new(name: str, data: bytes = b"", **kw):
        if name.lower() == "md4":
            obj = _FakeMD4()
            if data:
                obj.update(data)
            return obj
        return _orig_new(name, data, **kw)

    _stdlib_hashlib.new = _patched_new
    try:
        yield
    finally:
        _stdlib_hashlib.new = _orig_new


# ── Connector ─────────────────────────────────────────────────────────────────

class ADConnector:
    def __init__(
        self,
        dc_ip:       str,
        domain:      str,
        username:    str,
        password:    str   = "",
        lm_hash:     bytes = b"",
        nt_hash:     bytes = b"",
        use_ssl:     bool  = True,
        verify_cert: bool  = False,
    ):
        self.dc_ip       = dc_ip
        self.domain      = domain
        self.username    = username
        self.password    = password
        self.lm_hash     = lm_hash
        self.nt_hash     = nt_hash
        self.use_hash    = bool(nt_hash)   # True → pass-the-hash mode
        self.use_ssl     = use_ssl
        self.verify_cert = verify_cert
        self.conn        = None
        self.server      = None
        self.base_dn     = self._to_dn(domain)
        self.config_dn   = f"CN=Configuration,{self.base_dn}"
        self.schema_dn   = f"CN=Schema,{self.config_dn}"

    @staticmethod
    def _to_dn(domain: str) -> str:
        return ",".join(f"DC={p}" for p in domain.split("."))

    # ── Public connect entry-point ────────────────────────────────────────────

    def connect(self) -> bool:
        if self.use_ssl:
            if self._try_ldaps():
                return True
            print("[!] LDAPS failed, falling back to LDAP port 389...")
        return self._try_ldap()

    # ── LDAPS ─────────────────────────────────────────────────────────────────

    def _try_ldaps(self) -> bool:
        tls = Tls(
            validate=ssl.CERT_REQUIRED if self.verify_cert else ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT if self.verify_cert else ssl.PROTOCOL_TLS,
        )
        self.server = Server(self.dc_ip, port=636, use_ssl=True, tls=tls, get_info=ALL)

        if self.use_hash:
            return self._ntlm_pth_bind(port=636)

        attempts = [
            (NTLM,   f"{self.domain}\\{self.username}"),
            (NTLM,   f"{self.username}@{self.domain}"),
            (SIMPLE, f"{self.username}@{self.domain}"),
        ]
        for auth, user in attempts:
            try:
                self.conn = Connection(
                    self.server, user=user, password=self.password,
                    authentication=auth, auto_bind=True,
                )
                print(f"[+] Connected via LDAPS (port 636, auth={auth}, user={user})")
                return True
            except Exception as e:
                print(f"[!] LDAPS attempt failed (auth={auth}, user={user}): {e}")
        return False

    # ── LDAP ──────────────────────────────────────────────────────────────────

    def _try_ldap(self) -> bool:
        try:
            self.server = Server(self.dc_ip, port=389, get_info=ALL)

            if self.use_hash:
                return self._ntlm_pth_bind(port=389)

            self.conn = Connection(
                self.server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True,
            )
            print("[+] Connected via LDAP (port 389)")
            return True
        except LDAPException as e:
            print(f"[!] LDAP connection failed: {e}")
            return False

    # ── Pass-the-hash bind ────────────────────────────────────────────────────

    def _ntlm_pth_bind(self, port: int) -> bool:
        """
        Bind using NTLM with a pre-computed NT hash.

        ldap3 needs a non-empty string in the password field to build the
        NTLM negotiate message.  The actual hash injection happens via
        _pth_context(), which overrides hashlib.new('md4') for the duration
        of the Connection() call so the password string is never actually
        hashed — our bytes are returned directly.
        """
        proto = "LDAPS" if port == 636 else "LDAP"
        user  = f"{self.domain}\\{self.username}"

        try:
            with _pth_context(self.nt_hash):
                conn = Connection(
                    self.server,
                    user=user,
                    password="__pth__",   # placeholder; overridden by context
                    authentication=NTLM,
                    auto_bind=True,
                )
            self.conn = conn
            print(f"[+] Connected via {proto} (port {port}, pass-the-hash, user={user})")
            return True
        except Exception as e:
            print(f"[!] PtH {proto} bind failed (port {port}): {e}")
            return False

    # ── LDAP search helpers ───────────────────────────────────────────────────

    def search(
        self,
        filt:  str,
        attrs: list   = None,
        base:  str    = None,
        scope         = SUBTREE,
    ) -> List:
        b = base or self.base_dn
        a = attrs or [ALL_ATTRIBUTES]
        try:
            self.conn.search(
                search_base=b,
                search_filter=filt,
                search_scope=scope,
                attributes=a,
                size_limit=10000,
            )
            return self.conn.entries
        except LDAPException as e:
            print(f"  [~] LDAP search error ({filt[:60]}): {e}")
            return []

    def get_domain_object(self) -> Optional[object]:
        r = self.search("(objectClass=domain)", base=self.base_dn)
        return r[0] if r else None

    # ── Attribute accessors ───────────────────────────────────────────────────

    def attr_int(self, entry, attr: str, default: int = 0) -> int:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return default
        try:
            return int(str(v.value))
        except (ValueError, TypeError):
            return default

    def attr_str(self, entry, attr: str, default: str = "") -> str:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return default
        return str(v.value)

    def attr_list(self, entry, attr: str) -> List[str]:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return []
        val = v.value
        if isinstance(val, list):
            return [str(x) for x in val]
        return [str(val)]

    def resolve_sid(self, sid: str) -> str:
        """Resolve a SID string to sAMAccountName, or return the SID on failure."""
        try:
            results = self.search(
                f"(objectSid={sid})",
                ["sAMAccountName", "objectClass"],
                base=self.base_dn,
            )
            if results:
                name    = self.attr_str(results[0], "sAMAccountName")
                classes = self.attr_list(results[0], "objectClass")
                kind    = ("computer" if "computer" in classes else
                           "group"    if "group"    in classes else "user")
                return f"{name} ({kind})" if name else sid
        except Exception:
            pass
        return sid
