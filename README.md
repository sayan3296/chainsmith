# Chainsmith

A small personal PKI: root CA -> N intermediate CAs -> server certificates,
forged and reissued on command. Two independent implementations share one
on-disk store:

- `bash/chainsmith.sh` -- wraps the `openssl` CLI.
- `python/chainsmith.py` -- uses the `cryptography` library directly (no
  shelling out to `openssl`).

Both speak the same `store/` layout (standard OpenSSL CA directory
convention: `index.txt`, `serial`, `newcerts/`, PEM files), so a CA created
by one tool can issue certificates via the other, and either tool can
reissue an entity the other created. This shared store is also what a
future TUI or WebUI would sit on top of -- they'd just be another client
reading/writing the same `store/` and `meta.conf` files, no format changes
needed.

## Quick start

```sh
cd bash   # or: cd python, and swap chainsmith.sh -> "python3 chainsmith.py" below

# 1. Root CA (self-signed)
./chainsmith.sh init-ca --name root --cn "My Root CA" --org "My Org"

# 2. Intermediate CA, signed by root. Depth is unlimited -- an intermediate
#    can itself be used as --parent for another init-ca call.
./chainsmith.sh init-ca --name int1 --parent root --cn "My Intermediate CA" --org "My Org"

# 3. Server certificate, signed by the intermediate
./chainsmith.sh issue-server --name web1 --ca int1 --cn www.example.com \
  --san "DNS:www.example.com,DNS:example.com"

# 4. Reissue web1 with a new SAN and a shorter validity, keeping its key
./chainsmith.sh reissue web1 --san "DNS:www.example.com,DNS:new.example.com" --days 90

# 5. Reissue web1 with a brand-new keypair
./chainsmith.sh reissue web1 --rekey

# Inspect
./chainsmith.sh list
./chainsmith.sh show web1
```

Every generated file lives under `../store/<name>/`:

```
store/<name>/
  private/<name>.key.pem      # 0400
  csr/<name>.csr.pem
  certs/<name>.cert.pem
  certs/<name>-chain.cert.pem # full chain, this cert first
  meta.conf                   # recorded inputs -- see below
  archive/<timestamp>/        # prior key/csr/cert, written before each reissue
  openssl.cnf                 # CA entities only
  index.txt, serial, newcerts/  # CA entities only (issuance bookkeeping)
```

## Commands

- `init-ca --name NAME [--parent PARENT] --cn CN [--keytype rsa|ec] [--keysize N | --curve NAME] [--days N] [--org O] [--ou OU] [--country C] [--state ST] [--locality L]`
- `issue-server --name NAME --ca ISSUING_CA --cn CN [--san DNS:foo,IP:1.2.3.4] [--keytype rsa|ec] [--keysize N | --curve NAME] [--days N] [--org O] [--ou OU] [--country C] [--state ST] [--locality L]`
- `reissue NAME [--rekey] [--days N] [--cn CN] [--san SAN] [--org O] [--ou OU] [--country C] [--state ST] [--locality L] [--keytype rsa|ec] [--keysize N] [--curve NAME]`
- `list`
- `show NAME`

`reissue` never re-prompts: any flag you don't pass falls back to what's
already stored in that entity's `meta.conf`. Edit `meta.conf` by hand and
run `reissue NAME` with no flags to pick up the change, or just pass flags
directly.

Any required value not given on the command line is prompted for
interactively (`init-ca`/`issue-server` only, and only when stdin is a
terminal); in non-interactive/scripted use, pass every value you need
explicitly.

## Defaults

- Validity: root 7300 days (20y), intermediate 3650 days (10y), server 365
  days (1y).
- Keys: RSA 4096 (CA) / RSA 2048 (server) by default; pass `--keytype ec` for
  EC P-384 (CA) / P-256 (server).

## Two things that will break a chain -- by design, not by bug

- **Reissuing a CA with `--rekey`** changes its public key. Every child it
  previously signed carries the old key's fingerprint and will stop
  chaining. Reissue the children too.
- **Reissuing a CA with different subject fields** (CN/O/OU/C/ST/L) changes
  its Subject DN. Every child's baked-in Issuer DN now mismatches, and
  X.509 verification requires an exact name match. Reissue the children.

Both tools print a warning when they detect this. Note that reissuing a CA
*without* `--rekey` and *without* changing subject fields is always safe for
existing children -- the AKI extension is intentionally `keyid`-only (not
`keyid,issuer`), so a bare reissue (new serial, same key, same subject)
doesn't invalidate anything already issued.

## Cross-tool interoperability

Try it: create a root+intermediate with one tool, then issue a server cert
against that intermediate with the other:

```sh
cd bash && ./chainsmith.sh init-ca --name root --cn "Root"
./chainsmith.sh init-ca --name int1 --parent root --cn "Intermediate"
cd ../python && python3 chainsmith.py issue-server --name web1 --ca int1 --cn web1.example.com
```

This works because both tools write the same `meta.conf`, the same
`index.txt`/`serial` bookkeeping format, and (for CAs) the same rendered
`openssl.cnf` (the Python tool renders it from
`bash/templates/ca.cnf.tmpl` even though it never shells out to `openssl`
itself -- purely so the bash tool can later use `openssl ca`/`openssl req`
against a CA the Python tool created).

## Roadmap

A TUI and a WebUI are planned as additional front ends over the same
`store/` -- browsing the CA hierarchy, issuing/reissuing certs, and
inspecting `meta.conf`/expiry without touching the CLI. Neither exists yet;
the CLI tools above are the current interface.

## License

Chainsmith is licensed under the [MIT License](LICENSE).

## Credits

Chainsmith was designed and built as a human/AI pair-programming
collaboration: project direction, requirements, and review by the project
owner, with implementation, debugging, and cross-tool interoperability work
co-developed with Claude (Anthropic's Claude Code) as AI co-developer.
