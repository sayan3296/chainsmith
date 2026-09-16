# Examples

Full walkthroughs, with real commands and real captured output, for common
Chainsmith scenarios. Each is self-contained (creates its own root and
intermediate) and ends with a cleanup step -- these run against the real
`store/` directory, not a sandbox.

- [`01-root-and-intermediate-chain`](01-root-and-intermediate-chain/README.md) --
  building a multi-level CA chain and inspecting `list`/`build_chain` output.
- [`02-server-cert-issuance-variants`](02-server-cert-issuance-variants/README.md) --
  multiple SANs, EC vs RSA keys, and full subject fields.
- [`03-reissue-and-rekey`](03-reissue-and-rekey/README.md) --
  plain reissue, `--days`, `--rekey`, and the chain-breaking warnings.
- [`04-cross-tool-interoperability`](04-cross-tool-interoperability/README.md) --
  bash and python sharing one `store/`, in both directions.
- [`05-adcs-quirk-simulation`](05-adcs-quirk-simulation/README.md) --
  reproducing the AD CS PrintableString encoding bug with both tools.
- [`06-wildcard-san`](06-wildcard-san/README.md) --
  a wildcard domain in CN and SAN.
- [`07-multiple-wildcard-sans`](07-multiple-wildcard-sans/README.md) --
  one cert covering several distinct wildcard domains via a multi-entry SAN.
- [`08-sign-external-csr`](08-sign-external-csr/README.md) --
  signing a CSR generated outside chainsmith (a customer's own key/subject)
  against a root or intermediate, and how `reissue` differs for it.

See the top-level [`README.md`](../README.md) for command reference and
defaults.
