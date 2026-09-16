# Simulating the AD CS PrintableString encoding bug

`--adcs-quirk FIELD[,FIELD...]|all` on `issue-server`/`reissue` reproduces a
real-world Windows AD CS issuance bug: the CA blindly re-encodes a subject
RDN as ASN.1 PrintableString even when it contains characters outside that
charset (e.g. `&`). The result is technically ASN.1-invalid: lenient
parsers (`openssl` CLI, `dnf`, `curl`) accept it, strict ones (browsers)
reject it. This walkthrough triggers it with both tools and confirms the
resulting certs still cryptographically verify -- the corruption is purely
in the subject encoding, nothing else.

## bash

```sh
cd bash
./chainsmith.sh init-ca --name ex5-root --cn "Example5 Root CA"
./chainsmith.sh init-ca --name ex5-int --parent ex5-root --cn "Example5 Intermediate"

./chainsmith.sh issue-server --name ex5-web-bash --ca ex5-int --cn adcs-bash.example.com \
  --ou "R&D" --adcs-quirk OU
```
```
==> WARNING: --adcs-quirk applied to [OU] -- 'ex5-web-bash' is intentionally ASN.1-nonconformant (PrintableString content violating its charset) to reproduce a real-world CA issuance bug; expect strict parsers/browsers to reject it.
==> issued server certificate 'ex5-web-bash' (signed by 'ex5-int') -> .../store/ex5-web-bash/certs/ex5-web-bash.cert.pem
```

```sh
openssl asn1parse -in ../store/ex5-web-bash/certs/ex5-web-bash.cert.pem | grep -i 'R&D'
```
```
  109:d=5  hl=2 l=   3 prim: PRINTABLESTRING   :R&D
```

`PRINTABLESTRING` containing `&` is invalid on the wire -- `&` isn't in
PrintableString's charset (`A-Z a-z 0-9 space ' ( ) + , - . / : = ?`).
Lenient tooling doesn't care:

```sh
openssl x509 -in ../store/ex5-web-bash/certs/ex5-web-bash.cert.pem -noout -subject
```
```
subject=OU=R&D, CN=adcs-bash.example.com
```

Why bash needs help for this: OpenSSL's `string_mask` config (what
`bash/chainsmith.sh` otherwise relies on for subject encoding) only ever
auto-*escalates* to a wider *valid* string type when content doesn't fit
the narrower one -- it has no way to deliberately emit an invalid encoding,
since that's precisely the bug being simulated, not something OpenSSL
itself does. So bash's implementation instead lets `openssl ca` issue the
certificate completely normally, then re-tags the subject and re-signs it
with the parent CA's key via a small internal `python`+`cryptography`
helper (`bash/lib/adcs_quirk.py`) -- the same `_type`/`_validate=False`
technique the python tool uses directly (see below). This is the *only*
bash code path with a python dependency: `python3` and the `cryptography`
package are required only when `--adcs-quirk` is actually passed; every
other bash command stays fully python-free.

And critically, the certificate still cryptographically verifies -- the
re-sign-after-retagging step is cryptographically correct, so the
corruption never touches the signature:

```sh
openssl verify -CAfile ../store/ex5-root/certs/ex5-root.cert.pem \
  -untrusted ../store/ex5-int/certs/ex5-int.cert.pem \
  ../store/ex5-web-bash/certs/ex5-web-bash.cert.pem
```
```
../store/ex5-web-bash/certs/ex5-web-bash.cert.pem: OK
```

## python

Same flag, same result -- python does the retagging natively instead of
shelling out. `cryptography`'s public API validates PrintableString content
and refuses to build one containing `&`; `_type=_ASN1Type.PrintableString,
_validate=False` on `x509.NameAttribute` is its own private escape hatch
for constructing intentionally-nonconformant certificates (the same
mechanism its own test suite uses), which is exactly what's needed here:

```sh
cd python
python3 chainsmith.py init-ca --name ex5-root-py --cn "Example5 Root CA (python)"
python3 chainsmith.py init-ca --name ex5-int-py --parent ex5-root-py --cn "Example5 Intermediate (python)"

python3 chainsmith.py issue-server --name ex5-web-py --ca ex5-int-py --cn adcs-py.example.com \
  --ou "R&D" --adcs-quirk OU
```
```
WARNING: --adcs-quirk applied to ['OU'] -- the issued certificate is intentionally ASN.1-nonconformant (PrintableString content violating its charset) to reproduce a real-world CA issuance bug; expect strict parsers/browsers to reject it.
issued server certificate 'ex5-web-py' (signed by 'ex5-int-py') -> .../store/ex5-web-py/certs/ex5-web-py.cert.pem
```

```sh
openssl asn1parse -in ../store/ex5-web-py/certs/ex5-web-py.cert.pem | grep -i 'R&D'
```
```
  118:d=5  hl=2 l=   3 prim: PRINTABLESTRING   :R&D
```

```sh
openssl verify -CAfile ../store/ex5-root-py/certs/ex5-root-py.cert.pem \
  -untrusted ../store/ex5-int-py/certs/ex5-int-py.cert.pem \
  ../store/ex5-web-py/certs/ex5-web-py.cert.pem
```
```
../store/ex5-web-py/certs/ex5-web-py.cert.pem: OK
```

## It's one-off, not persisted

A later plain `reissue` (no `--adcs-quirk`) produces a normal cert again --
the corruption is never written to `meta.conf`:

```sh
python3 chainsmith.py reissue ex5-web-py
openssl asn1parse -in ../store/ex5-web-py/certs/ex5-web-py.cert.pem | grep -i 'R&D'
```
```
reissued 'ex5-web-py' (type=server, rekey=0) -> .../store/ex5-web-py/certs/ex5-web-py.cert.pem
  118:d=5  hl=2 l=   3 prim: UTF8STRING        :R&D
```

## Cleanup

```sh
rm -rf ../../store/ex5-root ../../store/ex5-int ../../store/ex5-web-bash \
       ../../store/ex5-root-py ../../store/ex5-int-py ../../store/ex5-web-py
```
