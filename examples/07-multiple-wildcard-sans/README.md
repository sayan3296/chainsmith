# Multiple wildcard domains in one SAN list

Extending [`06-wildcard-san`](../06-wildcard-san/README.md): a single
server cert can cover several distinct wildcard domains at once by listing
each as its own `DNS:` entry in `--san`, comma-separated -- exactly the
same mechanism as a normal multi-hostname SAN list, just with `*` in each
entry.

Run from `bash/` (equivalent from `python/` with `python3 chainsmith.py`).

## Setup

```sh
./chainsmith.sh init-ca --name ex7-root --cn "Example7 Root CA"
./chainsmith.sh init-ca --name ex7-int --parent ex7-root --cn "Example7 Intermediate"
```

## Issue a server cert covering three different wildcard domains

```sh
./chainsmith.sh issue-server --name ex7-web --ca ex7-int --cn "*.example.com" \
  --san "DNS:*.example.com,DNS:*.example.net,DNS:*.staging.example.io"
```

```
X509v3 Subject Alternative Name:
    DNS:*.example.com, DNS:*.example.net, DNS:*.staging.example.io
...
==> issued server certificate 'ex7-web' (signed by 'ex7-int') -> .../store/ex7-web/certs/ex7-web.cert.pem
```

All three wildcard entries are present, in the order given, alongside
whichever one matches the CN (`*.example.com` here, matching the CA/B
Forum-style convention of also including the CN as a SAN entry -- CN alone
isn't checked by modern browsers, only SAN is). There's no special
"wildcard count" limit in either tool; `--san` just splits on commas and
tags each entry `DNS:`/`IP:` (see
`bash/lib/common.sh:san_to_alt_names` / `python/pki/ca.py:parse_san`), so
this scales to as many SAN entries -- wildcard or not, mixed freely -- as
you need.

## Cleanup

```sh
rm -rf ../../store/ex7-root ../../store/ex7-int ../../store/ex7-web
```
