"""Subcommand wiring for Chainsmith's python edition. Mirrors
bash/chainsmith.sh exactly: init-ca, issue-server, reissue, list, show."""
import argparse
import datetime
import sys

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from . import ca, store

_ADCS_QUIRK_FIELDS = {"CN", "O", "OU", "C", "ST", "L"}
_EKU_OIDS = {"client": ExtendedKeyUsageOID.CLIENT_AUTH}

_EXTENSION_NAMES = {
    ExtensionOID.BASIC_CONSTRAINTS: "basicConstraints",
    ExtensionOID.KEY_USAGE: "keyUsage",
    ExtensionOID.EXTENDED_KEY_USAGE: "extendedKeyUsage",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subjectAltName",
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: "subjectKeyIdentifier",
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "authorityKeyIdentifier",
}


def prompt_if_missing(value, prompt, default=""):
    if value:
        return value
    if sys.stdin.isatty():
        suffix = f" [{default}]" if default else ""
        resp = input(f"{prompt}{suffix}: ").strip()
        return resp or default
    return default


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def _add_subject_args(p):
    p.add_argument("--org")
    p.add_argument("--ou")
    p.add_argument("--country")
    p.add_argument("--state")
    p.add_argument("--locality")


def _add_key_args(p):
    p.add_argument("--keytype", choices=["rsa", "ec"])
    p.add_argument("--keysize", type=int)
    p.add_argument("--curve")


def _parse_adcs_quirk(value):
    """Parses --adcs-quirk's value ('all' or a comma-separated list of field
    codes) into a set of field codes, or None if not given."""
    if not value:
        return None
    if value.strip().lower() == "all":
        return set(_ADCS_QUIRK_FIELDS)
    fields = {f.strip().upper() for f in value.split(",") if f.strip()}
    bad = fields - _ADCS_QUIRK_FIELDS
    if bad:
        die(f"unknown --adcs-quirk field(s) {sorted(bad)} "
            f"(use one of {sorted(_ADCS_QUIRK_FIELDS)} or 'all')")
    return fields


def _validate_eku(value):
    """Validates --eku's value (comma-separated additional EKU names to
    include alongside the always-present serverAuth; currently only
    'client' is supported). Returns the normalized string to store in
    meta.conf ("" if not given)."""
    if not value:
        return ""
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    bad = [t for t in tokens if t not in _EKU_OIDS]
    if bad:
        die(f"unknown --eku value(s) {bad} (currently supported: {sorted(_EKU_OIDS)})")
    return ",".join(tokens)


def _eku_oids(value):
    """Turns a validated, stored EKU string (see _validate_eku) into the
    list of ExtendedKeyUsageOID values sign_from_csr expects."""
    if not value:
        return []
    return [_EKU_OIDS[t] for t in value.split(",") if t]


def build_parser():
    parser = argparse.ArgumentParser(prog="chainsmith.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-ca", help="create a root or intermediate CA")
    p.add_argument("--name", required=True)
    p.add_argument("--parent")
    p.add_argument("--cn")
    p.add_argument("--days", type=int)
    _add_key_args(p)
    _add_subject_args(p)
    p.set_defaults(func=cmd_init_ca)

    p = sub.add_parser("issue-server", help="issue a leaf server certificate")
    p.add_argument("--name", required=True)
    p.add_argument("--ca", required=True, dest="ca_name")
    p.add_argument("--cn")
    p.add_argument("--san")
    p.add_argument("--days", type=int)
    _add_key_args(p)
    _add_subject_args(p)
    p.add_argument("--adcs-quirk", metavar="FIELD[,FIELD...]|all",
                    help="force the named subject field(s) (or 'all') to be "
                         "encoded as PrintableString regardless of charset, "
                         "reproducing a real-world Windows AD CS issuance bug")
    p.add_argument("--eku", metavar="client",
                    help="add clientAuth alongside the always-present "
                         "serverAuth (mTLS-style certs); persisted to "
                         "meta.conf, so it survives plain reissues")
    p.set_defaults(func=cmd_issue_server)

    p = sub.add_parser("sign-csr", help="sign an externally-generated CSR as a server cert")
    p.add_argument("--name", required=True)
    p.add_argument("--ca", required=True, dest="ca_name")
    p.add_argument("--csr", required=True, help="path to a PEM-encoded CSR file")
    p.add_argument("--days", type=int)
    p.add_argument("--eku", metavar="client",
                    help="add clientAuth alongside the always-present serverAuth")
    p.set_defaults(func=cmd_sign_csr)

    p = sub.add_parser("reissue", help="reissue an existing CA or server cert")
    p.add_argument("name")
    p.add_argument("--rekey", action="store_true")
    p.add_argument("--days", type=int)
    p.add_argument("--cn")
    p.add_argument("--san")
    _add_key_args(p)
    _add_subject_args(p)
    p.add_argument("--adcs-quirk", metavar="FIELD[,FIELD...]|all",
                    help="server certs only -- force the named subject "
                         "field(s) (or 'all') to be encoded as PrintableString "
                         "regardless of charset, reproducing a real-world "
                         "Windows AD CS issuance bug")
    p.add_argument("--csr", help="sign-csr entities only -- path to a new "
                                  "PEM-encoded CSR to replace the stored one")
    p.add_argument("--eku", metavar="client",
                    help="server certs only -- add clientAuth alongside "
                         "serverAuth; applies even to sign-csr entities "
                         "since it's chainsmith-owned, not part of the CSR")
    p.set_defaults(func=cmd_reissue)

    p = sub.add_parser("list", help="list every entity in the store")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="print a decoded certificate")
    p.add_argument("name")
    p.set_defaults(func=cmd_show)

    return parser


def cmd_init_ca(args):
    name = args.name
    if store.entity_dir(name).exists():
        die(f"'{name}' already exists in the store; use reissue instead")

    cn = prompt_if_missing(args.cn, "Common Name")
    if not cn:
        die("Common Name is required")

    if args.parent:
        entity_type = "intermediate"
        if not (store.entity_dir(args.parent) / "meta.conf").is_file():
            die(f"parent CA '{args.parent}' not found")
    else:
        entity_type = "root"

    keytype = args.keytype or "rsa"
    if keytype == "rsa":
        keysize, curve = str(args.keysize or 4096), ""
    else:
        keysize, curve = "", args.curve or "secp384r1"
    days = str(args.days or (7300 if entity_type == "root" else 3650))

    meta = {
        "NAME": name, "TYPE": entity_type, "PARENT": args.parent or "", "CN": cn,
        "ORG": args.org or "", "OU": args.ou or "", "COUNTRY": args.country or "",
        "STATE": args.state or "", "LOCALITY": args.locality or "",
        "KEYTYPE": keytype, "KEYSIZE": keysize, "CURVE": curve, "DAYS": days,
        "SAN": "", "CREATED_AT": now_iso(), "REISSUE_COUNT": "0",
    }

    store.mkdir_entity_skeleton(name)
    key = ca.generate_key(meta)
    ca.write_private_key(name, key)

    if entity_type == "root":
        ca.self_sign_root(name, meta, key)
    else:
        csr = ca.build_csr(name, meta, key)
        ca.sign_from_csr(name, csr, args.parent, days, "intermediate_ca")
    store.init_ca_bookkeeping(name)
    store.render_ca_config(name, days)

    store.meta_write(name, meta)
    store.build_chain(name)
    print(f"created {entity_type} CA '{name}' -> {store.entity_dir(name)}/certs/{name}.cert.pem")


def cmd_issue_server(args):
    name = args.name
    if store.entity_dir(name).exists():
        die(f"'{name}' already exists in the store; use reissue instead")
    ca_name = args.ca_name
    if not (store.entity_dir(ca_name) / "meta.conf").is_file():
        die(f"issuing CA '{ca_name}' not found")

    cn = prompt_if_missing(args.cn, "Common Name")
    if not cn:
        die("Common Name is required")
    san = prompt_if_missing(args.san, "Subject Alternative Names (DNS:foo,IP:1.2.3.4)", f"DNS:{cn}")

    keytype = args.keytype or "rsa"
    if keytype == "rsa":
        keysize, curve = str(args.keysize or 4096), ""
    else:
        keysize, curve = "", args.curve or "prime256v1"
    days = str(args.days or 365)

    eku = _validate_eku(args.eku)

    meta = {
        "NAME": name, "TYPE": "server", "PARENT": ca_name, "CN": cn,
        "ORG": args.org or "", "OU": args.ou or "", "COUNTRY": args.country or "",
        "STATE": args.state or "", "LOCALITY": args.locality or "",
        "KEYTYPE": keytype, "KEYSIZE": keysize, "CURVE": curve, "DAYS": days,
        "SAN": san, "CREATED_AT": now_iso(), "REISSUE_COUNT": "0", "EKU": eku,
    }

    adcs_quirk_fields = _parse_adcs_quirk(args.adcs_quirk)

    store.mkdir_entity_skeleton(name)
    key = ca.generate_key(meta)
    ca.write_private_key(name, key)
    csr = ca.build_csr(name, meta, key)
    ca.sign_from_csr(name, csr, ca_name, days, "server",
                      adcs_quirk_fields=adcs_quirk_fields, extra_eku=_eku_oids(eku))

    store.meta_write(name, meta)
    store.build_chain(name)
    print(f"issued server certificate '{name}' (signed by '{ca_name}') -> "
          f"{store.entity_dir(name)}/certs/{name}.cert.pem")
    if adcs_quirk_fields:
        print(f"WARNING: --adcs-quirk applied to {sorted(adcs_quirk_fields)} -- "
              "the issued certificate is intentionally ASN.1-nonconformant "
              "(PrintableString content violating its charset) to reproduce a "
              "real-world CA issuance bug; expect strict parsers/browsers to "
              "reject it.", file=sys.stderr)


def cmd_sign_csr(args):
    name = args.name
    if store.entity_dir(name).exists():
        die(f"'{name}' already exists in the store; use reissue instead")
    ca_name = args.ca_name
    if not (store.entity_dir(ca_name) / "meta.conf").is_file():
        die(f"issuing CA '{ca_name}' not found")

    days = str(args.days or 365)
    try:
        csr, raw = ca.load_external_csr(args.csr)
    except store.PkiError as e:
        die(str(e))
    eku = _validate_eku(args.eku)

    meta = {
        "NAME": name, "TYPE": "server", "PARENT": ca_name, "CN": "",
        "ORG": "", "OU": "", "COUNTRY": "", "STATE": "", "LOCALITY": "",
        "KEYTYPE": "", "KEYSIZE": "", "CURVE": "", "DAYS": days, "SAN": "",
        "CREATED_AT": now_iso(), "REISSUE_COUNT": "0", "EXTERNAL_CSR": "1",
        "EKU": eku,
    }

    store.mkdir_entity_skeleton(name)
    (store.entity_dir(name) / "csr" / f"{name}.csr.pem").write_bytes(raw)
    ca.sign_from_csr(name, csr, ca_name, days, "server", extra_eku=_eku_oids(eku))

    store.meta_write(name, meta)
    store.build_chain(name)
    print(f"signed external CSR -> entity '{name}' (signed by '{ca_name}') -> "
          f"{store.entity_dir(name)}/certs/{name}.cert.pem")


def cmd_reissue(args):
    name = args.name
    meta = store.meta_load(name)
    entity_type, parent = meta["TYPE"], meta["PARENT"]
    is_external = bool(meta.get("EXTERNAL_CSR"))
    if args.adcs_quirk and entity_type != "server":
        die(f"--adcs-quirk only applies to server certificates "
            f"(entity '{name}' is type '{entity_type}')")
    adcs_quirk_fields = _parse_adcs_quirk(args.adcs_quirk)
    if args.eku and entity_type != "server":
        die(f"--eku only applies to server certificates "
            f"(entity '{name}' is type '{entity_type}')")

    if is_external:
        bad = [flag for flag, val in (
            ("--rekey", args.rekey), ("--cn", args.cn), ("--san", args.san),
            ("--org", args.org), ("--ou", args.ou), ("--country", args.country),
            ("--state", args.state), ("--locality", args.locality),
            ("--keytype", args.keytype), ("--keysize", args.keysize),
            ("--curve", args.curve),
        ) if val]
        if bad:
            die(f"{', '.join(bad)} don't apply to '{name}': it was created via sign-csr "
                f"(subject/SAN/key come from the CSR, not chainsmith) -- use --csr PATH "
                f"to replace it instead")
    elif args.csr:
        die(f"--csr only applies to entities created via sign-csr "
            f"('{name}' has a chainsmith-managed key)")

    orig_subject = {k: meta[k] for k in ("CN", "ORG", "OU", "COUNTRY", "STATE", "LOCALITY")}

    if args.cn:
        meta["CN"] = args.cn
    if args.san:
        meta["SAN"] = args.san
    if args.org:
        meta["ORG"] = args.org
    if args.ou:
        meta["OU"] = args.ou
    if args.country:
        meta["COUNTRY"] = args.country
    if args.state:
        meta["STATE"] = args.state
    if args.locality:
        meta["LOCALITY"] = args.locality
    if args.days:
        meta["DAYS"] = str(args.days)
    if args.eku:
        meta["EKU"] = _validate_eku(args.eku)
    if args.keytype:
        meta["KEYTYPE"] = args.keytype
        if args.keytype == "rsa":
            meta["KEYSIZE"] = str(args.keysize or meta["KEYSIZE"] or 4096)
            meta["CURVE"] = ""
        else:
            meta["KEYSIZE"] = ""
            meta["CURVE"] = args.curve or meta["CURVE"] or "prime256v1"
    else:
        if args.keysize:
            meta["KEYSIZE"] = str(args.keysize)
        if args.curve:
            meta["CURVE"] = args.curve

    if entity_type in ("root", "intermediate"):
        new_subject = {k: meta[k] for k in orig_subject}
        if new_subject != orig_subject:
            print(f"WARNING: subject fields for CA '{name}' changed. Certificates it "
                  "already issued carry the OLD issuer DN and will no longer chain by "
                  "name to the new certificate; reissue those children too.", file=sys.stderr)

    store.archive_entity(name)
    meta["REISSUE_COUNT"] = str(int(meta["REISSUE_COUNT"] or 0) + 1)

    if is_external:
        csr_path = store.entity_dir(name) / "csr" / f"{name}.csr.pem"
        if args.csr:
            try:
                csr, raw = ca.load_external_csr(args.csr)
            except store.PkiError as e:
                die(str(e))
            csr_path.write_bytes(raw)
        else:
            try:
                csr, _ = ca.load_external_csr(str(csr_path))
            except store.PkiError as e:
                die(str(e))
        ca.sign_from_csr(name, csr, parent, meta["DAYS"], "server",
                          adcs_quirk_fields=adcs_quirk_fields,
                          extra_eku=_eku_oids(meta["EKU"]))
    else:
        if args.rekey:
            key = ca.generate_key(meta)
            ca.write_private_key(name, key)
        else:
            key = ca.load_private_key(name)

        if entity_type == "root":
            ca.self_sign_root(name, meta, key)
            store.render_ca_config(name, meta["DAYS"])
            if args.rekey:
                print(f"WARNING: root '{name}' was rekeyed. Any intermediates previously "
                      "signed by the old root key no longer chain to it; reissue them too.",
                      file=sys.stderr)
        elif entity_type == "intermediate":
            csr = ca.build_csr(name, meta, key)
            ca.sign_from_csr(name, csr, parent, meta["DAYS"], "intermediate_ca")
            store.render_ca_config(name, meta["DAYS"])
        elif entity_type == "server":
            csr = ca.build_csr(name, meta, key)
            ca.sign_from_csr(name, csr, parent, meta["DAYS"], "server",
                              adcs_quirk_fields=adcs_quirk_fields,
                              extra_eku=_eku_oids(meta["EKU"]))
        else:
            die(f"unknown entity type '{entity_type}' for '{name}'")

    store.meta_write(name, meta)
    store.build_chain(name)
    print(f"reissued '{name}' (type={entity_type}, rekey={int(args.rekey)}) -> "
          f"{store.entity_dir(name)}/certs/{name}.cert.pem")
    if adcs_quirk_fields:
        print(f"WARNING: --adcs-quirk applied to {sorted(adcs_quirk_fields)} -- "
              "the reissued certificate is intentionally ASN.1-nonconformant "
              "(PrintableString content violating its charset) to reproduce a "
              "real-world CA issuance bug; expect strict parsers/browsers to "
              "reject it.", file=sys.stderr)


def cmd_list(args):
    if not store.STORE_DIR.is_dir():
        die(f"store not found at {store.STORE_DIR}")
    print(f"{'NAME':<20} {'TYPE':<12} {'PARENT':<20} {'DAYS':<10} {'KEY':<9} EXPIRES")
    for d in sorted(store.STORE_DIR.iterdir()):
        if not (d / "meta.conf").is_file():
            continue
        name = d.name
        meta = store.meta_load(name)
        expiry = "n/a"
        cert_path = d / "certs" / f"{name}.cert.pem"
        if cert_path.is_file():
            expiry = ca.load_cert(name).not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")
        key_source = "external" if meta.get("EXTERNAL_CSR") else "local"
        print(f"{name:<20} {meta['TYPE']:<12} {meta['PARENT'] or '-':<20} "
              f"{meta['DAYS']:<10} {key_source:<9} {expiry}")


def cmd_show(args):
    name = args.name
    cert_path = store.entity_dir(name) / "certs" / f"{name}.cert.pem"
    if not cert_path.is_file():
        die(f"no certificate found for '{name}'")
    cert = ca.load_cert(name)
    print("Certificate:")
    print(f"  Subject: {cert.subject.rfc4514_string()}")
    print(f"  Issuer: {cert.issuer.rfc4514_string()}")
    print(f"  Serial Number: {cert.serial_number} (0x{cert.serial_number:x})")
    print(f"  Not Before: {cert.not_valid_before} UTC")
    print(f"  Not After: {cert.not_valid_after} UTC")
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        print(f"  Public Key: RSA ({pubkey.key_size} bits)")
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        print(f"  Public Key: EC ({pubkey.curve.name})")
    print("  Extensions:")
    for ext in cert.extensions:
        label = _EXTENSION_NAMES.get(ext.oid, ext.oid.dotted_string)
        print(f"    {label}: critical={ext.critical}")
        print(f"      {ext.value}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except store.PkiError as e:
        die(str(e))


if __name__ == "__main__":
    main()
