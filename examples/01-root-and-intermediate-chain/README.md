# Root CA + multi-level intermediate chain

`init-ca`'s depth is unlimited: any existing CA (root or intermediate) can
be used as `--parent` for another `init-ca` call. This walkthrough builds a
3-level chain (root -> intermediate A -> intermediate B) and inspects the
result.

Run from `bash/` (swap `./chainsmith.sh` for `python3 chainsmith.py` from
`python/` for the other implementation -- output is equivalent).

## 1. Create the root

```sh
./chainsmith.sh init-ca --name ex1-root --cn "Example Root CA" --org "Example Org"
```

```
==> created root CA 'ex1-root' -> /home/pnq/saydas/chainsmith/store/ex1-root/certs/ex1-root.cert.pem
```

## 2. Create intermediate A, signed by the root

```sh
./chainsmith.sh init-ca --name ex1-int-a --parent ex1-root --cn "Example Intermediate A" --org "Example Org"
```

```
Using configuration from .../store/ex1-root/openssl.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4096 (0x1000)
        ...
        Subject:
            organizationName          = Example Org
            commonName                = Example Intermediate A
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
...
==> created intermediate CA 'ex1-int-a' -> .../store/ex1-int-a/certs/ex1-int-a.cert.pem
```

(python's output for the same step is a plain one-line confirmation;
`openssl ca`'s verbose certificate dump above is specific to the bash tool
wrapping the `openssl` CLI.)

## 3. Create intermediate B, signed by intermediate A -- same command, different parent

```sh
./chainsmith.sh init-ca --name ex1-int-b --parent ex1-int-a --cn "Example Intermediate B" --org "Example Org"
```

Nothing about this step differs from step 2 other than `--parent
ex1-int-a` instead of `--parent ex1-root` -- `init-ca` doesn't care whether
its parent is itself a root or an intermediate.

## 4. Inspect the chain

```sh
./chainsmith.sh list
```

```
NAME                 TYPE         PARENT               DAYS       EXPIRES
ex1-int-a            intermediate ex1-root             3650       Sep 13 08:02:21 2036 GMT
ex1-int-b            intermediate ex1-int-a            3650       Sep 13 08:02:22 2036 GMT
ex1-root             root         -                    7300       Sep 11 08:02:20 2046 GMT
```

`build_chain` (called automatically after every `init-ca`/`issue-server`/
`reissue`) walks the `PARENT` links and writes
`certs/<name>-chain.cert.pem`, that entity's cert first:

```sh
grep -c "BEGIN CERTIFICATE" ../store/ex1-int-b/certs/ex1-int-b-chain.cert.pem
# 3
openssl pkcs7 -print_certs -noout \
  -in <(openssl crl2pkcs7 -nocrl -certfile ../store/ex1-int-b/certs/ex1-int-b-chain.cert.pem)
```

```
subject=O=Example Org, CN=Example Intermediate B
subject=O=Example Org, CN=Example Intermediate A
subject=O=Example Org, CN=Example Root CA
```

Any depth works the same way -- keep passing the most recently created
intermediate as the next `--parent`.

## Cleanup

```sh
rm -rf ../../store/ex1-root ../../store/ex1-int-a ../../store/ex1-int-b
```
