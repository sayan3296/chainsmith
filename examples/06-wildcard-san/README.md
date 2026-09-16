# Wildcard domain in CN and SAN

`issue-server`'s `--cn`/`--san` are passed straight through as strings --
neither tool treats `*` specially, so a wildcard domain works exactly like
any other hostname.

Run from `bash/` (equivalent from `python/` with `python3 chainsmith.py`).

## Setup

```sh
./chainsmith.sh init-ca --name ex6-root --cn "Example6 Root CA"
./chainsmith.sh init-ca --name ex6-int --parent ex6-root --cn "Example6 Intermediate"
```

## Issue a server cert for `*.example.com`

```sh
./chainsmith.sh issue-server --name ex6-web --ca ex6-int --cn "*.example.com" --san "DNS:*.example.com"
```

```
X509v3 Subject Alternative Name:
    DNS:*.example.com
...
==> issued server certificate 'ex6-web' (signed by 'ex6-int') -> .../store/ex6-web/certs/ex6-web.cert.pem
```

```sh
./chainsmith.sh show ex6-web
```

```
Subject: CN=*.example.com
...
X509v3 Subject Alternative Name:
    DNS:*.example.com
```

Note `--san` isn't optional here in the sense of getting it for free from
`--cn`: if you omit `--san` entirely it defaults to `DNS:<CN>`, which
*does* correctly carry the wildcard through (`DNS:*.example.com`) since
it's built directly from the CN string -- so `--cn "*.example.com"` alone
is enough. The explicit `--san` above is just spelled out for clarity.

## Cleanup

```sh
rm -rf ../../store/ex6-root ../../store/ex6-int ../../store/ex6-web
```
