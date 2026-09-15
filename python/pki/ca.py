"""Key/CSR/certificate generation via the `cryptography` library.

Mirrors the bash+OpenSSL tool's extension policy exactly (see
bash/templates/ca.cnf.tmpl) so certs from either tool interoperate:
  - CAs (root/intermediate): basicConstraints critical CA:true, keyUsage
    critical (digitalSignature, cRLSign, keyCertSign), SKI=hash, AKI=keyid.
  - Server (leaf): basicConstraints CA:false (non-critical), keyUsage
    critical (digitalSignature, keyEncipherment), EKU=serverAuth,
    SKI=hash, AKI=keyid, subjectAltName from the SAN field.
  - AKI is keyid-only (no issuer+serial) so that reissuing a CA (which
    always changes its serial, even without --rekey) never breaks
    already-issued children as long as the CA's key is unchanged.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import store

EC_CURVES = {
    "secp256r1": ec.SECP256R1,
    "prime256v1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
    "secp224r1": ec.SECP224R1,
}


def generate_key(meta):
    keytype = meta["KEYTYPE"]
    if keytype == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(meta["KEYSIZE"]))
    if keytype == "ec":
        curve_cls = EC_CURVES.get(meta["CURVE"])
        if curve_cls is None:
            raise store.PkiError(f"unsupported curve '{meta['CURVE']}'")
        return ec.generate_private_key(curve_cls())
    raise store.PkiError(f"unsupported keytype '{keytype}' (use rsa or ec)")


def write_private_key(name, key):
    path = store.entity_dir(name) / "private" / f"{name}.key.pem"
    if path.exists():
        # On --rekey the file already exists chmod 400 from its previous
        # generation; restore write permission before overwriting it.
        path.chmod(0o600)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o400)
    return path


def load_private_key(name):
    path = store.entity_dir(name) / "private" / f"{name}.key.pem"
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_cert(name):
    path = store.entity_dir(name) / "certs" / f"{name}.cert.pem"
    return x509.load_pem_x509_certificate(path.read_bytes())


def build_name(meta):
    attrs = []
    if meta.get("COUNTRY"):
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, meta["COUNTRY"]))
    if meta.get("STATE"):
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, meta["STATE"]))
    if meta.get("LOCALITY"):
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, meta["LOCALITY"]))
    if meta.get("ORG"):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, meta["ORG"]))
    if meta.get("OU"):
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, meta["OU"]))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, meta["CN"]))
    return x509.Name(attrs)


def parse_san(san_text):
    names = []
    for entry in san_text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            raise store.PkiError(f"invalid SAN entry '{entry}' (expected TYPE:value)")
        kind, value = entry.split(":", 1)
        kind = kind.upper()
        if kind == "DNS":
            names.append(x509.DNSName(value))
        elif kind == "IP":
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        else:
            raise store.PkiError(f"unsupported SAN type '{kind}' (use DNS: or IP:)")
    return names


def build_csr(name, meta, key):
    builder = x509.CertificateSigningRequestBuilder().subject_name(build_name(meta))
    if meta["TYPE"] == "server":
        san = meta.get("SAN") or f"DNS:{meta['CN']}"
        builder = builder.add_extension(
            x509.SubjectAlternativeName(parse_san(san)), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    path = store.entity_dir(name) / "csr" / f"{name}.csr.pem"
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return csr


def _write_cert(name, cert):
    path = store.entity_dir(name) / "certs" / f"{name}.cert.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def self_sign_root(name, meta, key):
    subject = build_name(meta)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=int(meta["DAYS"])))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    _write_cert(name, cert)
    return cert


def sign_from_csr(name, csr, parent_name, days, extension_kind):
    """Signs `csr` with parent_name's key, writes certs/<name>.cert.pem, and
    records the issuance in the parent's index.txt/serial/newcerts (the same
    bookkeeping `openssl ca` performs, so bash and python stay interoperable).
    extension_kind is 'intermediate_ca' or 'server'.
    """
    parent_key = load_private_key(parent_name)
    parent_cert = load_cert(parent_name)
    serial_hex = format(store.read_serial(parent_name), "X")
    serial_int = int(serial_hex, 16)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=int(days))

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(parent_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_int)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_key.public_key()),
            critical=False,
        )
    )

    if extension_kind == "intermediate_ca":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
    elif extension_kind == "server":
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            builder = builder.add_extension(san_ext.value, critical=False)
        except x509.ExtensionNotFound:
            pass
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        ).add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                          crl_sign=False, content_commitment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    else:
        raise store.PkiError(f"unknown extension_kind '{extension_kind}'")

    cert = builder.sign(parent_key, hashes.SHA256())
    _write_cert(name, cert)

    newcerts_path = store.entity_dir(parent_name) / "newcerts" / f"{serial_hex}.pem"
    newcerts_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    store.append_index_entry(parent_name, serial_hex, not_after, name_to_dn(csr.subject))
    store.bump_serial(parent_name)
    return cert


_DN_OID_ORDER = (
    ("C", NameOID.COUNTRY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("CN", NameOID.COMMON_NAME),
)


def name_to_dn(name):
    """Formats an x509.Name as the '/C=.../CN=...' string OpenSSL writes into
    index.txt, so index.txt entries look identical whichever tool wrote them.
    """
    parts = []
    for label, oid in _DN_OID_ORDER:
        for attr in name.get_attributes_for_oid(oid):
            parts.append(f"/{label}={attr.value}")
    return "".join(parts)
