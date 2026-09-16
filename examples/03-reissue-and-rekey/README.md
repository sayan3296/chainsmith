# Reissue and rekey

`reissue` never re-prompts: any flag you don't pass falls back to what's
already stored in that entity's `meta.conf`. Every reissue archives the
prior key/CSR/cert to `archive/<timestamp>/` first. This walkthrough covers
a plain reissue, a validity change, and the two situations that print a
chain-breaking WARNING.

Run from `bash/` (python's behavior and warning text are the same; only the
`openssl ca` verbose log is bash-specific).

## Setup

```sh
./chainsmith.sh init-ca --name ex3-root --cn "Example3 Root CA"
./chainsmith.sh init-ca --name ex3-int --parent ex3-root --cn "Example3 Intermediate" --org "Example Org"
./chainsmith.sh issue-server --name ex3-web --ca ex3-int --cn web.example.com
```

```sh
./chainsmith.sh show ex3-web | grep -E 'Serial|Not Before|Not After'
```
```
Serial Number: 4096 (0x1000)
Not Before: Sep 16 08:11:21 2026 GMT
Not After : Sep 16 08:11:21 2027 GMT
```

## 1. Plain reissue -- no flags, meta.conf supplies everything

```sh
./chainsmith.sh reissue ex3-web
```
```
==> archived previous material for 'ex3-web' to .../store/ex3-web/archive/20260916T081128Z
==> reissued 'ex3-web' (type=server, rekey=0) -> .../store/ex3-web/certs/ex3-web.cert.pem
```

New serial, same validity length, same key (rekey=0), same CN/subject --
only the serial and Not Before/Not After shift to "now":

```
Serial Number: 4097 (0x1001)
Not Before: Sep 16 08:11:28 2026 GMT
Not After : Sep 16 08:11:28 2027 GMT
```

## 2. Shortening validity with `--days`

```sh
./chainsmith.sh reissue ex3-web --days 90
```
```
Not After : Dec 15 08:11:51 2026 GMT (90 days)
```

`--days` (like every other reissue flag) only overrides for this call --
it does **not** update the entity's stored default for the *next* reissue
unless you check `meta.conf`: reissue does persist whatever value was used
back into `meta.conf`, so a subsequent plain `reissue` will keep using `90`
until told otherwise.

## 3. `--rekey` -- only warns on a root

```sh
./chainsmith.sh reissue ex3-root --rekey
```
```
==> archived previous material for 'ex3-root' to .../store/ex3-root/archive/20260916T081245Z
==> WARNING: root 'ex3-root' was rekeyed. Any intermediates previously signed by the old root key no longer chain to it; reissue them too.
==> reissued 'ex3-root' (type=root, rekey=1) -> .../store/ex3-root/certs/ex3-root.cert.pem
```

Note: as implemented today, this explicit rekey WARNING is only printed
when reissuing a **root**. Rekeying an intermediate or a server cert also
changes its key (breaking anything signed by an intermediate's old key,
same underlying issue) but does not currently print this warning -- worth
knowing if you're relying on the warning rather than tracking rekeys
yourself.

## 4. Changing a CA's subject fields -- warns on root or intermediate

```sh
./chainsmith.sh reissue ex3-int --org "New Org Name"
```
```
==> WARNING: subject fields for CA 'ex3-int' changed. Certificates it already issued carry the OLD issuer DN and will no longer chain by name to the new certificate; reissue those children too.
==> archived previous material for 'ex3-int' to .../store/ex3-int/archive/20260916T081251Z
==> reissued 'ex3-int' (type=intermediate, rekey=0) -> .../store/ex3-int/certs/ex3-int.cert.pem
```

Unlike the rekey warning, this one fires for **either** `root` or
`intermediate` (see `README.md`'s "Two things that will break a chain"
section for why: it's the Issuer DN mismatch, not the key, that breaks the
chain here).

## Cleanup

```sh
rm -rf ../../store/ex3-root ../../store/ex3-int ../../store/ex3-web
```
