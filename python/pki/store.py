"""On-disk store layout shared with the bash implementation.

Both tools operate on the same store/ directory using the standard OpenSSL
CA conventions (index.txt/serial/newcerts) so a CA created by one tool can
issue or be issued from by the other.
"""
import datetime
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
STORE_DIR = ROOT_DIR / "store"
CA_CNF_TEMPLATE = ROOT_DIR / "bash" / "templates" / "ca.cnf.tmpl"

META_FIELDS = [
    "NAME", "TYPE", "PARENT", "CN", "ORG", "OU", "COUNTRY", "STATE",
    "LOCALITY", "KEYTYPE", "KEYSIZE", "CURVE", "DAYS", "SAN",
    "CREATED_AT", "REISSUE_COUNT",
]

_META_LINE_RE = re.compile(r'^([A-Z_]+)="(.*)"$')


class PkiError(Exception):
    pass


def entity_dir(name):
    return STORE_DIR / name


def _escape(value):
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace('"', '\\"')
    return value


def _unescape(value):
    out = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in ("\\", '"'):
            out.append(value[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def meta_write(name, meta):
    """Writes store/<name>/meta.conf. `meta` is a dict covering META_FIELDS."""
    path = entity_dir(name) / "meta.conf"
    lines = []
    for key in META_FIELDS:
        lines.append(f'{key}="{_escape(meta.get(key, ""))}"')
    path.write_text("\n".join(lines) + "\n")


def meta_load(name):
    """Reads store/<name>/meta.conf into a dict covering META_FIELDS."""
    path = entity_dir(name) / "meta.conf"
    if not path.is_file():
        raise PkiError(f"unknown entity '{name}' (no {path})")
    meta = {key: "" for key in META_FIELDS}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _META_LINE_RE.match(line)
        if m:
            meta[m.group(1)] = _unescape(m.group(2))
    return meta


def parent_of(name):
    path = entity_dir(name) / "meta.conf"
    if not path.is_file():
        return ""
    for line in path.read_text().splitlines():
        m = _META_LINE_RE.match(line.strip())
        if m and m.group(1) == "PARENT":
            return _unescape(m.group(2))
    return ""


def mkdir_entity_skeleton(name):
    d = entity_dir(name)
    (d / "private").mkdir(parents=True, exist_ok=True)
    (d / "csr").mkdir(parents=True, exist_ok=True)
    (d / "certs").mkdir(parents=True, exist_ok=True)
    (d / "archive").mkdir(parents=True, exist_ok=True)
    (d / "private").chmod(0o700)


def render_ca_config(name, days):
    """Renders bash/templates/ca.cnf.tmpl into store/<name>/openssl.cnf.

    Python doesn't use this file itself (certs are built directly via the
    `cryptography` library), but writing it means the bash+OpenSSL tool can
    later use `openssl ca`/`openssl req` against a CA the Python tool
    created -- required for real cross-tool interoperability on a shared
    store. Both tools render from the same template, so the extension
    policy (see bash/templates/ca.cnf.tmpl) has one source of truth.
    """
    if not CA_CNF_TEMPLATE.is_file():
        return
    d = entity_dir(name)
    text = CA_CNF_TEMPLATE.read_text()
    text = text.replace("__DIR__", str(d))
    text = text.replace("__NAME__", name)
    text = text.replace("__DEFAULT_DAYS__", str(days))
    (d / "openssl.cnf").write_text(text)


def init_ca_bookkeeping(name):
    """Sets up index.txt/serial/crlnumber/newcerts for a CA-capable entity."""
    d = entity_dir(name)
    (d / "newcerts").mkdir(parents=True, exist_ok=True)
    (d / "index.txt").write_text("")
    (d / "index.txt.attr").write_text("unique_subject = no\n")
    (d / "serial").write_text("1000\n")
    (d / "crlnumber").write_text("1000\n")


def read_serial(ca_name):
    text = (entity_dir(ca_name) / "serial").read_text().strip()
    return int(text, 16)


def bump_serial(ca_name):
    n = read_serial(ca_name)
    hex_str = format(n + 1, "X")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    (entity_dir(ca_name) / "serial").write_text(hex_str + "\n")


def subject_dn(meta):
    """Builds the '/C=.../CN=...' style DN string, matching the bash tool's
    build_subject ordering (also the ordering openssl itself writes into
    index.txt), from a meta dict."""
    parts = []
    for field, key in (("C", "COUNTRY"), ("ST", "STATE"), ("L", "LOCALITY"),
                        ("O", "ORG"), ("OU", "OU"), ("CN", "CN")):
        v = meta.get(key, "")
        if v:
            parts.append(f"/{field}={v}")
    return "".join(parts)


def append_index_entry(ca_name, serial_hex, not_after, subject):
    """Appends an OpenSSL-index.txt-compatible row to ca_name's database."""
    expiry = not_after.strftime("%y%m%d%H%M%SZ")
    line = f"V\t{expiry}\t\t{serial_hex}\tunknown\t{subject}\n"
    with open(entity_dir(ca_name) / "index.txt", "a") as f:
        f.write(line)


def archive_entity(name):
    d = entity_dir(name)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = d / "archive" / ts
    dest.mkdir(parents=True, exist_ok=True)
    for rel in (f"private/{name}.key.pem", f"csr/{name}.csr.pem",
                f"certs/{name}.cert.pem", f"certs/{name}-chain.cert.pem",
                "meta.conf"):
        src = d / rel
        if src.is_file():
            dest_file = dest / Path(rel).name
            dest_file.write_bytes(src.read_bytes())
    return dest


def build_chain(name):
    """Writes certs/<name>-chain.cert.pem by walking PARENT links."""
    d = entity_dir(name)
    out = d / "certs" / f"{name}-chain.cert.pem"
    chunks = []
    cur = name
    while cur:
        chunks.append((entity_dir(cur) / "certs" / f"{cur}.cert.pem").read_bytes())
        cur = parent_of(cur)
    out.write_bytes(b"".join(chunks))
