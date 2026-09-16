# Cross-tool interoperability, both directions

Both tools read and write the same `store/` layout (`meta.conf`,
`index.txt`/`serial`/`newcerts/`, and -- for CAs -- the same rendered
`openssl.cnf`), so a CA created by one can issue certificates via the
other. This walkthrough proves it in both directions and confirms the
resulting chains actually verify.

## Direction 1: bash creates the CA, python issues off it

```sh
cd bash
./chainsmith.sh init-ca --name ex4-root --cn "Example4 Root (bash)"
./chainsmith.sh init-ca --name ex4-int --parent ex4-root --cn "Example4 Intermediate (bash)"

cd ../python
python3 chainsmith.py issue-server --name ex4-web-py --ca ex4-int --cn web-py.example.com
```
```
issued server certificate 'ex4-web-py' (signed by 'ex4-int') -> .../store/ex4-web-py/certs/ex4-web-py.cert.pem
```

Python's own `list` sees the bash-created root/intermediate correctly
typed, because it's reading the same `meta.conf` files bash wrote:

```sh
python3 chainsmith.py list
```
```
NAME                 TYPE         PARENT               DAYS       EXPIRES
ex4-int              intermediate ex4-root             3650       Sep 13 08:13:32 2036 GMT
ex4-root             root         -                    7300       Sep 11 08:13:32 2046 GMT
ex4-web-py           server       ex4-int              365        Sep 16 08:13:33 2027 GMT
```

And the resulting chain -- bash-signed intermediate, python-built leaf --
verifies end to end with plain `openssl verify`:

```sh
openssl verify -CAfile ../store/ex4-root/certs/ex4-root.cert.pem \
  -untrusted ../store/ex4-int/certs/ex4-int.cert.pem \
  ../store/ex4-web-py/certs/ex4-web-py.cert.pem
```
```
../store/ex4-web-py/certs/ex4-web-py.cert.pem: OK
```

## Direction 2: python creates the CA, bash issues off it

```sh
cd python
python3 chainsmith.py init-ca --name ex4b-root --cn "Example4b Root (python)"
python3 chainsmith.py init-ca --name ex4b-int --parent ex4b-root --cn "Example4b Intermediate (python)"

cd ../bash
./chainsmith.sh issue-server --name ex4b-web-bash --ca ex4b-int --cn web-bash.example.com
```

`bash`'s `list` in turn sees the python-created entities:

```sh
./chainsmith.sh list
```
```
NAME                 TYPE         PARENT               DAYS       EXPIRES
ex4b-int             intermediate ex4b-root            3650       Sep 13 08:13:46 2036 GMT
ex4b-root            root         -                    7300       Sep 11 08:13:45 2046 GMT
ex4b-web-bash        server       ex4b-int             365        Sep 16 08:13:46 2027 GMT
```

```sh
openssl verify -CAfile ../store/ex4b-root/certs/ex4b-root.cert.pem \
  -untrusted ../store/ex4b-int/certs/ex4b-int.cert.pem \
  ../store/ex4b-web-bash/certs/ex4b-web-bash.cert.pem
```
```
../store/ex4b-web-bash/certs/ex4b-web-bash.cert.pem: OK
```

## Why this works

- Both tools write identical `meta.conf` (same fields, same escaping).
- Both tools maintain the CA `index.txt`/`serial`/`newcerts/` bookkeeping
  in the same format `openssl ca` itself expects/produces.
- For CAs, both render the same `bash/templates/ca.cnf.tmpl` into
  `store/<name>/openssl.cnf` -- python renders it purely so the bash tool
  can later run `openssl ca`/`openssl req` against a CA python created,
  even though python itself never shells out to `openssl`.
- Both apply the identical certificate extension policy (SKI=hash,
  AKI=keyid-only, matching KeyUsage/BasicConstraints/EKU per entity type),
  so a cert from either tool chains and verifies under standard X.509
  rules regardless of which tool built which link.

## Cleanup

```sh
rm -rf ../../store/ex4-root ../../store/ex4-int ../../store/ex4-web-py \
       ../../store/ex4b-root ../../store/ex4b-int ../../store/ex4b-web-bash
```
