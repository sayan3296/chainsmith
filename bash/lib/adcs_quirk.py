#!/usr/bin/env python3
"""Internal helper for bash/chainsmith.sh's --adcs-quirk. Not a public CLI.

Loads an already-issued certificate, re-tags the named subject RDN
attributes as PrintableString regardless of charset -- mimicking a
real-world Windows AD CS issuance bug where the CA blindly re-encodes RDN
values as PrintableString even when they contain disallowed characters
(e.g. '&'), producing a certificate that lenient parsers (openssl CLI, dnf)
accept but strict ones (browsers) reject. Sibling implementation:
python/pki/ca.py:_adcs_retag_subject (same technique, deliberately
duplicated here rather than imported, to keep the bash and python trees
independent).

Re-signs the result with the issuing CA's private key, since patching the
subject invalidates the original signature, and writes it to every given
output path (bash/chainsmith.sh points this at both certs/<name>.cert.pem
and the CA's newcerts/<serial>.pem bookkeeping copy).

Usage: adcs_quirk.py CERT_PEM PARENT_KEY_PEM FIELDS OUT [OUT ...]
  FIELDS is a comma-separated list of CN/O/OU/C/ST/L, or 'all'.
"""
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

_FIELD_OIDS = {
    "C": NameOID.COUNTRY_NAME, "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME, "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "CN": NameOID.COMMON_NAME,
}


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_fields(raw):
    if raw.strip().lower() == "all":
        return set(_FIELD_OIDS)
    fields = {f.strip().upper() for f in raw.split(",") if f.strip()}
    bad = fields - set(_FIELD_OIDS)
    if bad:
        die(f"unknown field(s) {sorted(bad)} (use one of {sorted(_FIELD_OIDS)} or 'all')")
    return fields


def retag_subject(name, fields):
    oids = {_FIELD_OIDS[f] for f in fields}
    attrs = []
    for rdn in name.rdns:
        for attr in rdn:
            if attr.oid in oids:
                attrs.append(x509.NameAttribute(
                    attr.oid, attr.value,
                    _type=_ASN1Type.PrintableString, _validate=False))
            else:
                attrs.append(attr)
    return x509.Name(attrs)


def main(argv):
    if len(argv) < 4:
        die("usage: adcs_quirk.py CERT_PEM PARENT_KEY_PEM FIELDS OUT [OUT ...]")
    cert_path, key_path, fields_raw, *out_paths = argv
    fields = parse_fields(fields_raw)

    try:
        cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    except (OSError, ValueError) as e:
        die(f"failed to load certificate '{cert_path}': {e}")
    try:
        parent_key = serialization.load_pem_private_key(
            open(key_path, "rb").read(), password=None)
    except (OSError, ValueError) as e:
        die(f"failed to load private key '{key_path}': {e}")

    builder = (
        x509.CertificateBuilder()
        .subject_name(retag_subject(cert.subject, fields))
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before)
        .not_valid_after(cert.not_valid_after)
    )
    for ext in cert.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)

    new_cert = builder.sign(parent_key, hashes.SHA256())
    pem = new_cert.public_bytes(serialization.Encoding.PEM)
    for out_path in out_paths:
        with open(out_path, "wb") as f:
            f.write(pem)


if __name__ == "__main__":
    main(sys.argv[1:])
