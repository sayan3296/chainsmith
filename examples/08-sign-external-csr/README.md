# Signing an externally-generated CSR

`issue-server` always generates its own key *and* CSR. `sign-csr` is for
the other real-world shape: someone else generated a CSR (their own key,
their own subject) and you just need an existing root or intermediate CA
in the store to sign it. Chainsmith never sees or holds a private key for
the result -- only the CSR and the certificate it signs.

Run from `bash/` (equivalent from `python/` with `python3 chainsmith.py`).

## Setup: a CA, and a CSR chainsmith never touches

```sh
./chainsmith.sh init-ca --name ex8-root --cn "Example8 Root CA"
./chainsmith.sh init-ca --name ex8-int --parent ex8-root --cn "Example8 Intermediate"
```

Generate a CSR the way a customer actually would -- plain `openssl req`,
its own throwaway key, no chainsmith involved:

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout customer.key.pem \
  -subj "/O=Customer Corp/CN=customer-app.example.com" \
  -addext "subjectAltName=DNS:customer-app.example.com,DNS:www.customer-app.example.com" \
  -out customer.csr.pem
```

## Sign it against the intermediate

```sh
./chainsmith.sh sign-csr --name ex8-web --ca ex8-int --csr customer.csr.pem
```
```
...
==> signed external CSR -> entity 'ex8-web' (signed by 'ex8-int') -> .../store/ex8-web/certs/ex8-web.cert.pem
```

The issued certificate's subject and SAN are exactly what the CSR carried
-- chainsmith doesn't add or override anything:

```sh
openssl x509 -in ../store/ex8-web/certs/ex8-web.cert.pem -noout -subject
openssl x509 -in ../store/ex8-web/certs/ex8-web.cert.pem -noout -ext subjectAltName
```
```
subject=O=Customer Corp, CN=customer-app.example.com
X509v3 Subject Alternative Name:
    DNS:customer-app.example.com, DNS:www.customer-app.example.com
```

And, critically, there's no local private key for this entity:

```sh
ls ../store/ex8-web/private/
# (empty)
```

`meta.conf` records this explicitly via `EXTERNAL_CSR="1"` (with
`CN`/`ORG`/`SAN`/`KEYTYPE`/etc. all left blank -- the real subject lives in
the certificate and in `csr/ex8-web.csr.pem`, not duplicated into
`meta.conf`), and `list` surfaces it in a `KEY` column:

```sh
./chainsmith.sh list
```
```
NAME                 TYPE         PARENT               DAYS       KEY       EXPIRES
ex8-int              intermediate ex8-root             3650       local     ...
ex8-root             root         -                    7300       local     ...
ex8-web              server       ex8-int              365        external  ...
```

The chain verifies exactly as any other cert would:

```sh
openssl verify -CAfile ../store/ex8-root/certs/ex8-root.cert.pem \
  -untrusted ../store/ex8-int/certs/ex8-int.cert.pem \
  ../store/ex8-web/certs/ex8-web.cert.pem
```
```
../store/ex8-web/certs/ex8-web.cert.pem: OK
```

## `--ca` isn't restricted to intermediates

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout customer2.key.pem \
  -subj "/O=Customer Corp/CN=direct-from-root.example.com" \
  -addext "subjectAltName=DNS:direct-from-root.example.com" \
  -out customer2.csr.pem

./chainsmith.sh sign-csr --name ex8-web-root --ca ex8-root --csr customer2.csr.pem
openssl verify -CAfile ../store/ex8-root/certs/ex8-root.cert.pem ../store/ex8-web-root/certs/ex8-web-root.cert.pem
```
```
../store/ex8-web-root/certs/ex8-web-root.cert.pem: OK
```

## A tampered CSR is rejected, not silently signed

```sh
# (copy customer.csr.pem to tampered.csr.pem, flip one base64 character
# near the end, corrupting only the signature bytes)
./chainsmith.sh sign-csr --name ex8-tampered --ca ex8-int --csr tampered.csr.pem
```
```
...
error:1C880004:Provider routines:rsa_verify_directly:RSA lib:...
error:06880006:asn1 encoding routines:ASN1_item_verify_ctx:EVP lib:...
```

`openssl ca` verifies a CSR's self-signature automatically before issuing
(the `Check that the request matches the signature` / `Signature ok` lines
already visible in every issuance) -- a corrupted signature aborts the
script via `set -euo pipefail`. Python's `cryptography` library doesn't
verify this on load by default, so chainsmith checks explicitly:

```sh
cd ../python
python3 chainsmith.py sign-csr --name ex8-tampered --ca ex8-int --csr ../bash/tampered.csr.pem
```
```
error: CSR 'tampered.csr.pem' signature does not verify
```

## `reissue` on a sign-csr entity

A plain `reissue` re-signs the *same* stored CSR -- new serial and
validity, same subject/SAN, since there's no chainsmith-managed subject to
regenerate from:

```sh
./chainsmith.sh reissue ex8-web
```
```
==> archived previous material for 'ex8-web' to .../store/ex8-web/archive/20260916T093907Z
==> reissued 'ex8-web' (type=server, rekey=0) -> .../store/ex8-web/certs/ex8-web.cert.pem
```

`--rekey` and the subject flags (`--cn`, `--org`, ...) are rejected --
there's no chainsmith-managed key or subject to change:

```sh
./chainsmith.sh reissue ex8-web --rekey
```
```
error: --rekey/--cn/--san/--org/--ou/--country/--state/--locality/--keytype/--keysize/--curve don't apply to 'ex8-web': it was created via sign-csr (subject/SAN/key come from the CSR, not chainsmith) -- use --csr PATH to replace it instead
```

Conversely, `--csr` is rejected on a normal (chainsmith-managed) entity:

```sh
./chainsmith.sh reissue ex8-int --csr customer.csr.pem
```
```
error: --csr only applies to entities created via sign-csr ('ex8-int' has a chainsmith-managed key)
```

To actually replace the CSR being signed (e.g. the customer rotated their
key and sent a new one), pass `--csr PATH`:

```sh
./chainsmith.sh reissue ex8-web --csr customer2.csr.pem
openssl x509 -in ../store/ex8-web/certs/ex8-web.cert.pem -noout -subject
```
```
subject=O=Customer Corp, CN=direct-from-root.example.com
```

The old CSR is archived under `archive/<timestamp>/` first, same as any
other reissue.

`--adcs-quirk` still works on sign-csr entities too, since they're still
`TYPE=server` under the hood:

```sh
./chainsmith.sh reissue ex8-web --adcs-quirk OU
```

## Cleanup

```sh
rm -rf ../../store/ex8-root ../../store/ex8-int ../../store/ex8-web \
       ../../store/ex8-web-root ../../store/ex8-web-py ../../store/ex8-quirk \
       ../../store/ex8-tampered ../../store/ex8-tampered2 ../../store/ex8-tampered-py
rm -f customer.key.pem customer.csr.pem customer2.key.pem customer2.csr.pem \
      customer3.key.pem customer3.csr.pem tampered.csr.pem
```
