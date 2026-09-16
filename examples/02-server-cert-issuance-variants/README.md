# Server cert issuance variants

`issue-server` accepts multiple SANs, either key type, and full subject
fields. This walkthrough issues three server certs off the same
intermediate, one per variant.

Run from `bash/` (swap for `python3 chainsmith.py` from `python/` -- output
is equivalent; the SAN/key-type/subject behavior is identical, only the
bash tool's `openssl ca` verbose issuance log differs).

## Setup

```sh
./chainsmith.sh init-ca --name ex2-root --cn "Example2 Root CA"
./chainsmith.sh init-ca --name ex2-int --parent ex2-root --cn "Example2 Intermediate"
```

## 1. Multiple SANs (DNS + IP)

```sh
./chainsmith.sh issue-server --name ex2-web-san --ca ex2-int --cn www.example.com \
  --san "DNS:www.example.com,DNS:example.com,IP:10.0.0.5"
```

Relevant part of the issued certificate:

```
X509v3 Subject Alternative Name:
    DNS:www.example.com, DNS:example.com, IP Address:10.0.0.5
```

`--san` is a comma-separated `TYPE:value` list; only `DNS:` and `IP:` are
supported (`lib/common.sh:san_to_alt_names` / `pki/ca.py:parse_san`). If
`--san` is omitted entirely, it defaults to `DNS:<CN>`.

## 2. EC key instead of the RSA default

```sh
./chainsmith.sh issue-server --name ex2-web-ec --ca ex2-int --cn ec.example.com --keytype ec
```

```sh
openssl pkey -in ../store/ex2-web-ec/private/ex2-web-ec.key.pem -text -noout | head -1
```

```
Private-Key: (256 bit)
```

`--keytype ec` defaults to curve `prime256v1` (P-256) for server certs, or
pass `--curve NAME` for a different one. (CAs created with `--keytype ec`
default to `secp384r1`/P-384 instead -- see `README.md`'s Defaults
section.) The default without `--keytype` is RSA 4096 for server certs
(same as CAs).

## 3. Full subject fields

```sh
./chainsmith.sh issue-server --name ex2-web-subj --ca ex2-int --cn full.example.com \
  --org "Example Org" --ou "Platform Engineering" --country US --state California \
  --locality "San Francisco"
```

```sh
./chainsmith.sh show ex2-web-subj
```

```
Subject: C=US, ST=California, L=San Francisco, O=Example Org, OU=Platform Engineering, CN=full.example.com
```

Any of `--org`/`--ou`/`--country`/`--state`/`--locality` can be omitted
independently -- only `--cn` is required (or prompted for interactively if
omitted and stdin is a terminal).

## Cleanup

```sh
rm -rf ../../store/ex2-root ../../store/ex2-int \
       ../../store/ex2-web-san ../../store/ex2-web-ec ../../store/ex2-web-subj
```
