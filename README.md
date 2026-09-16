# Chainsmith

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4EAA25?logo=gnu-bash&logoColor=white)](bash/)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](python/)

A small personal PKI: root CA → N intermediate CAs → server
certificates, forged and reissued on command. Two independent
implementations share one on-disk store -- `bash/chainsmith.sh` wraps
`openssl`; `python/chainsmith.py` uses `cryptography` directly -- so a
CA created by one can issue from or be reissued by the other. Same
shared store a future TUI/WebUI would sit on top of.

## 🚀 Quick start

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

<details>
<summary>On-disk layout (<code>store/&lt;name&gt;/</code>)</summary>

```
store/<name>/
  private/<name>.key.pem      # 0400; absent for sign-csr entities
  csr/<name>.csr.pem
  certs/<name>.cert.pem
  certs/<name>-chain.cert.pem # full chain, this cert first
  meta.conf                   # recorded inputs
  archive/<timestamp>/        # prior key/csr/cert, written before each reissue
  openssl.cnf                 # CA entities only
  index.txt, serial, newcerts/  # CA entities only (issuance bookkeeping)
```

</details>

## 📚 Examples

Nine full walkthroughs (real commands, real captured output) live under
[`examples/`](examples/): multi-level CA chains, server cert variants
(SAN/EC/RSA/subject fields/wildcards), reissue/rekey, cross-tool interop,
the AD CS quirk simulation, signing externally-generated CSRs, and mTLS
client-auth certs. See [`examples/README.md`](examples/README.md) for the
full index.

## 🛠️ Commands

| Command | Purpose |
|---|---|
| `init-ca` | Create a root or intermediate CA |
| `issue-server` | Issue a leaf server certificate |
| `sign-csr` | Sign an externally-generated CSR — see below |
| `reissue` | Re-issue an existing CA or server cert |
| `list` | List every entity in the store (type, parent, key source, expiry) |
| `show` | Print a decoded certificate (`openssl x509 -text`) |

<details>
<summary>Full flag reference</summary>

`key-flags`/`subject-flags` below are shorthand, not literal syntax:

```
init-ca --name NAME [--parent PARENT] --cn CN [--days N] [key-flags] [subject-flags]
issue-server --name NAME --ca ISSUING_CA --cn CN [--san DNS:foo,IP:1.2.3.4] [--days N]
             [key-flags] [subject-flags] [--adcs-quirk FIELD[,FIELD...]|all] [--eku client]
sign-csr --name NAME --ca ISSUING_CA --csr PATH [--days N] [--eku client]
reissue NAME [--rekey] [--days N] [--cn CN] [--san SAN] [key-flags] [subject-flags]
        [--adcs-quirk FIELD[,FIELD...]|all] [--csr PATH] [--eku client]
list
show NAME
```

- `key-flags` = `[--keytype rsa|ec] [--keysize N | --curve NAME]`
- `subject-flags` = `[--org O] [--ou OU] [--country C] [--state ST] [--locality L]`

`--adcs-quirk` — see
[`examples/05-adcs-quirk-simulation`](examples/05-adcs-quirk-simulation/README.md).
`--eku` and `sign-csr`'s different `reissue` behavior — see "Client
certificate authentication (mTLS)" and "Signing externally-generated
CSRs" below.

`reissue` never re-prompts: any flag you don't pass falls back to
what's already stored in that entity's `meta.conf`. Edit `meta.conf` by
hand and run `reissue NAME` with no flags to pick up the change.

Any required value not given on the command line is prompted for
interactively (`init-ca`/`issue-server` only, and only when stdin is a
terminal); in non-interactive/scripted use, pass every value explicitly.

</details>

## ⚙️ Defaults

- Validity: root 7300 days (20y), intermediate 3650 days (10y), server 365
  days (1y).
- Keys: RSA 4096 (CA and server) by default; pass `--keytype ec` for
  EC P-384 (CA) / P-256 (server).

## ⚠️ Two things that will break a chain -- by design, not by bug

> [!WARNING]
> **Reissuing a CA with `--rekey`** changes its public key -- every
> child it signed carries the old key's fingerprint and stops chaining.

> [!WARNING]
> **Reissuing a CA with different subject fields** (CN/O/OU/C/ST/L)
> changes its Subject DN -- every child's Issuer DN now mismatches
> (X.509 requires an exact match).

Both tools print a warning when they detect either case -- reissue the
children too when it happens.

> [!TIP]
> A bare reissue (no `--rekey`, same subject) is always safe -- the AKI
> extension is intentionally `keyid`-only, so it never invalidates
> anything already issued.

## 📝 Signing externally-generated CSRs

<details>
<summary><code>sign-csr</code> signs a CSR generated elsewhere -- a customer's own key/subject -- against an existing CA</summary>

`sign-csr --name NAME --ca ISSUING_CA --csr PATH` signs a CSR
chainsmith never built itself: no key is generated or held for the
result, and `CN`/`O`/`OU`/`SAN`/etc. stay blank in `meta.conf` since the
real values live in the certificate and the CSR file itself:

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout customer.key.pem \
  -subj "/O=Customer Corp/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com" -out customer.csr.pem
./chainsmith.sh sign-csr --name web1 --ca int1 --csr customer.csr.pem
```

> [!NOTE]
> Both tools verify the CSR's self-signature before signing -- bash for
> free via `openssl ca`, python via an explicit `is_signature_valid`
> check -- so a tampered or malformed CSR is rejected, not silently
> accepted.

`reissue` differs here: `--rekey`/`--cn`/`--org`/etc. are rejected
(there's no chainsmith-managed key or subject to change). A plain
`reissue` re-signs the same stored CSR; `--csr PATH` swaps in a new one
(e.g. the customer rotated their key). See
[`examples/08-sign-external-csr`](examples/08-sign-external-csr/README.md).

</details>

## 🔐 Client certificate authentication (mTLS)

<details>
<summary><code>--eku client</code> adds clientAuth alongside serverAuth, persisted across reissues</summary>

Server certs default to `serverAuth` only. `--eku client` on
`issue-server`/`sign-csr`/`reissue` also includes `clientAuth`, for
certs that need to authenticate as both a TLS server and (mTLS) client:

```sh
./chainsmith.sh issue-server --name web1 --ca int1 --cn app.example.com --eku client
```

> [!NOTE]
> Unlike `--adcs-quirk`, this is durable: stored in `meta.conf`, so a
> plain `reissue` keeps the same EKU set. It also still applies to
> `sign-csr` entities' `reissue`, since EKU is chainsmith-decided, not
> part of the CSR. See
> [`examples/09-client-auth-eku`](examples/09-client-auth-eku/README.md).

</details>

## 🔗 Cross-tool interoperability

<details>
<summary>Create with one tool, issue or reissue with the other</summary>

```sh
cd bash && ./chainsmith.sh init-ca --name root --cn "Root"
./chainsmith.sh init-ca --name int1 --parent root --cn "Intermediate"
cd ../python && python3 chainsmith.py issue-server --name web1 --ca int1 --cn web1.example.com
```

Works because both tools write the same `meta.conf`, the same
`index.txt`/`serial` bookkeeping, and (for CAs) the same rendered
`openssl.cnf` -- python renders it from `bash/templates/ca.cnf.tmpl`
purely so bash can later act on a CA python created, even though python
itself never shells out to `openssl`.

</details>

## 🗺️ Roadmap

A TUI and a WebUI are planned as additional front ends over the same
`store/` -- browsing the CA hierarchy, issuing/reissuing certs, and
inspecting `meta.conf`/expiry without touching the CLI. Neither exists
yet; the CLI tools above are the current interface.

## 📜 License

Chainsmith is licensed under the [MIT License](LICENSE).

## 🙌 Credits

Chainsmith was designed and built as a human/AI pair-programming
collaboration: project direction, requirements, and review by the
project owner, with implementation, debugging, and cross-tool
interoperability work co-developed with Claude (Anthropic's Claude
Code) as AI co-developer.
