# Adding clientAuth alongside serverAuth (`--eku client`)

By default, server certs get `serverAuth` only. `--eku client` adds
`clientAuth` too -- mTLS-style certs that authenticate as both server and
client. Unlike `--adcs-quirk` (a one-off bug simulation), `--eku` is a
durable cert property: it's persisted to `meta.conf`, so a plain `reissue`
keeps the same EKU set.

Run from `bash/` (equivalent from `python/` with `python3 chainsmith.py`).

## Setup

```sh
./chainsmith.sh init-ca --name ex9-root --cn "Example9 Root CA"
./chainsmith.sh init-ca --name ex9-int --parent ex9-root --cn "Example9 Intermediate"
```

## Default: serverAuth only

```sh
./chainsmith.sh issue-server --name ex9-web-default --ca ex9-int --cn default.example.com
openssl x509 -in ../store/ex9-web-default/certs/ex9-web-default.cert.pem -noout -ext extendedKeyUsage
```
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication
```

## `--eku client`: both serverAuth and clientAuth

```sh
./chainsmith.sh issue-server --name ex9-web-mtls --ca ex9-int --cn mtls.example.com --eku client
openssl x509 -in ../store/ex9-web-mtls/certs/ex9-web-mtls.cert.pem -noout -ext extendedKeyUsage
```
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication, TLS Web Client Authentication
```

`meta.conf` records it:

```sh
grep EKU ../store/ex9-web-mtls/meta.conf
```
```
EKU="client"
```

## It also applies to `sign-csr`, since EKU is chainsmith-owned (not part of the CSR)

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout customer.key.pem \
  -subj "/O=Customer Corp/CN=customer-mtls.example.com" \
  -addext "subjectAltName=DNS:customer-mtls.example.com" \
  -out customer.csr.pem

./chainsmith.sh sign-csr --name ex9-web-signed --ca ex9-int --csr customer.csr.pem --eku client
openssl x509 -in ../store/ex9-web-signed/certs/ex9-web-signed.cert.pem -noout -ext extendedKeyUsage
```
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication, TLS Web Client Authentication
```

## Persistence: a plain `reissue` keeps the EKU set

```sh
./chainsmith.sh reissue ex9-web-mtls
openssl x509 -in ../store/ex9-web-mtls/certs/ex9-web-mtls.cert.pem -noout -ext extendedKeyUsage
```
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication, TLS Web Client Authentication
```

And you can add it later to a cert that didn't have it:

```sh
./chainsmith.sh reissue ex9-web-default --eku client
openssl x509 -in ../store/ex9-web-default/certs/ex9-web-default.cert.pem -noout -ext extendedKeyUsage
```
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication, TLS Web Client Authentication
```

## `--eku` still works on a `sign-csr` entity's reissue, even though most other flags don't

```sh
./chainsmith.sh reissue ex9-web-signed --eku client
```
```
==> reissued 'ex9-web-signed' (type=server, rekey=0) -> .../store/ex9-web-signed/certs/ex9-web-signed.cert.pem
```

While `--rekey` (or `--cn`/`--org`/etc.) on that same entity is still
rejected, since those *are* the CSR's content:

```sh
./chainsmith.sh reissue ex9-web-signed --rekey
```
```
error: --rekey/--cn/--san/--org/--ou/--country/--state/--locality/--keytype/--keysize/--curve don't apply to 'ex9-web-signed': it was created via sign-csr (subject/SAN/key come from the CSR, not chainsmith) -- use --csr PATH to replace it instead
```

## Validation

Unknown EKU values are rejected before any CA state changes (no wasted
serial), and `--eku` only applies to server certs:

```sh
./chainsmith.sh issue-server --name x --ca ex9-int --cn x --eku bogus
```
```
error: unknown --eku value 'bogus' (currently supported: client)
```

```sh
./chainsmith.sh reissue ex9-int --eku client
```
```
error: --eku only applies to server certificates ('ex9-int' is type 'intermediate')
```

## Cleanup

```sh
rm -rf ../../store/ex9-root ../../store/ex9-int \
       ../../store/ex9-web-default ../../store/ex9-web-mtls ../../store/ex9-web-signed
rm -f customer.key.pem customer.csr.pem
```
