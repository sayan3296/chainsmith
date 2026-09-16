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
  private/<name>.key.pem      # 0400; absent for sign-csr entities (see below)
  csr/<name>.csr.pem
  certs/<name>.cert.pem
  certs/<name>-chain.cert.pem # full chain, this cert first
  meta.conf                   # recorded inputs -- see below
  archive/<timestamp>/        # prior key/csr/cert, written before each reissue
  openssl.cnf                 # CA entities only
  index.txt, serial, newcerts/  # CA entities only (issuance bookkeeping)
```

## Examples

Nine full walkthroughs (real commands, real captured output) live under
[`examples/`](examples/): multi-level CA chains, server cert variants
(SAN/EC/RSA/subject fields/wildcards), reissue/rekey, cross-tool interop,
the AD CS quirk simulation, signing externally-generated CSRs, and mTLS
client-auth certs. See [`examples/README.md`](examples/README.md) for the
full index.

## Commands

```
init-ca --name NAME [--parent PARENT] --cn CN
        [--keytype rsa|ec] [--keysize N | --curve NAME] [--days N]
        [--org O] [--ou OU] [--country C] [--state ST] [--locality L]
```
Creates a root CA (no `--parent`) or an intermediate CA (`--parent` an
existing CA).

```
issue-server --name NAME --ca ISSUING_CA --cn CN
             [--san DNS:foo,IP:1.2.3.4] [--keytype rsa|ec]
             [--keysize N | --curve NAME] [--days N]
             [--org O] [--ou OU] [--country C] [--state ST] [--locality L]
             [--adcs-quirk FIELD[,FIELD...]|all] [--eku client]
```
Issues a leaf server certificate signed by `ISSUING_CA`. `--adcs-quirk`
force-encodes the named subject field(s) as PrintableString regardless of
charset, reproducing a real-world Windows AD CS issuance bug — see
[`examples/05-adcs-quirk-simulation`](examples/05-adcs-quirk-simulation/README.md).
`--eku` — see "Client certificate authentication (mTLS)" below.

```
sign-csr --name NAME --ca ISSUING_CA --csr PATH [--days N] [--eku client]
```
Signs a CSR generated outside chainsmith as a server certificate — see
"Signing externally-generated CSRs" below.

```
reissue NAME [--rekey] [--days N] [--cn CN] [--san SAN]
        [--org O] [--ou OU] [--country C] [--state ST] [--locality L]
        [--keytype rsa|ec] [--keysize N] [--curve NAME]
        [--adcs-quirk FIELD[,FIELD...]|all] [--csr PATH] [--eku client]
```
Re-issues an existing CA or server cert; any flag not given falls back
to what's stored in `meta.conf`. `--csr PATH` and `--eku` behave
differently for `sign-csr`-created entities — see "Signing
externally-generated CSRs" and "Client certificate authentication (mTLS)"
below.

```
list
```
Every entity in the store, with type, parent, key source (`local` vs
`external`), and expiry.

```
show NAME
```
Prints the decoded certificate (`openssl x509 -text`).

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

## Signing externally-generated CSRs

`sign-csr --name NAME --ca ISSUING_CA --csr PATH` covers the shape
`issue-server` doesn't: someone else generated the CSR -- their own key,
their own subject -- and you just need an existing root or intermediate to
sign it. Chainsmith never generates or holds a private key for the result;
`csr/<name>.csr.pem` is a copy of exactly what was submitted, and
`CN`/`O`/`OU`/`SAN`/etc. stay blank in `meta.conf` since the real values
live in the certificate and the CSR itself, not duplicated:

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout customer.key.pem \
  -subj "/O=Customer Corp/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com" -out customer.csr.pem
./chainsmith.sh sign-csr --name web1 --ca int1 --csr customer.csr.pem
```

Both tools verify the CSR's self-signature before signing it -- bash gets
this for free from `openssl ca`'s built-in check, python checks
`csr.is_signature_valid` explicitly since `cryptography` doesn't do this on
load -- so a tampered or malformed CSR is rejected, not silently accepted.

`reissue` works differently for these entities: there's no
chainsmith-managed key or subject to change, so `--rekey`/`--cn`/`--org`/
etc. are rejected. A plain `reissue` re-signs the same stored CSR (new
serial/validity, same subject); `--csr PATH` replaces it with a new one
(e.g. the customer rotated their key). See
[`examples/08-sign-external-csr`](examples/08-sign-external-csr/README.md).

## Client certificate authentication (mTLS)

Server certs default to `serverAuth` only. Pass `--eku client` to
`issue-server`, `sign-csr`, or `reissue` to also include `clientAuth`, for
certs that need to authenticate as both a TLS server and (e.g. in an mTLS
setup) a client:

```sh
./chainsmith.sh issue-server --name web1 --ca int1 --cn app.example.com --eku client
```

Unlike `--adcs-quirk`, this is a durable property: it's stored in
`meta.conf`, so a later plain `reissue` keeps the same EKU set. It also
still applies to `sign-csr`-created entities' `reissue` (unlike the flags
rejected for them above) since EKU is chainsmith-decided, not part of the
submitted CSR. See
[`examples/09-client-auth-eku`](examples/09-client-auth-eku/README.md).

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
