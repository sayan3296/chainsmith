#!/usr/bin/env bash
# Chainsmith (bash+OpenSSL edition): root/intermediate CAs and server
# certs, forged and reissued on command.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SELF_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
Usage: chainsmith.sh <command> [options]

Commands:
  init-ca --name NAME [--parent PARENT] --cn CN
          [--keytype rsa|ec] [--keysize N] [--curve NAME] [--days N]
          [--org O] [--ou OU] [--country C] [--state ST] [--locality L]
      Creates a root CA (no --parent) or an intermediate CA (--parent NAME
      of an existing CA). Depth is unlimited: an intermediate can itself be
      used as --parent for another init-ca call.

  issue-server --name NAME --ca ISSUING_CA --cn CN
          [--san DNS:foo,DNS:bar,IP:1.2.3.4] [--keytype rsa|ec]
          [--keysize N] [--curve NAME] [--days N]
          [--org O] [--ou OU] [--country C] [--state ST] [--locality L]
          [--adcs-quirk FIELD[,FIELD...]|all] [--eku client]
      Issues a leaf server certificate signed by ISSUING_CA. --adcs-quirk
      force-encodes the named subject field(s) (CN/O/OU/C/ST/L, or "all")
      as PrintableString regardless of charset, reproducing a real-world
      Windows AD CS issuance bug; requires python3+cryptography and is
      one-off (not stored in meta.conf). --eku client adds clientAuth
      alongside the always-present serverAuth (mTLS-style certs); stored
      in meta.conf, so it persists across plain reissues.

  sign-csr --name NAME --ca ISSUING_CA --csr PATH [--days N] [--eku client]
      Signs an externally-generated CSR (a foreign key, a subject the
      requester controls) as a server certificate, issued by ISSUING_CA
      (root or intermediate). Unlike issue-server, chainsmith never
      generates or holds a private key for this entity -- only the CSR
      (copied into csr/<name>.csr.pem) and the resulting certificate.
      --eku behaves as in issue-server.

  reissue NAME [--rekey] [--days N] [--cn CN] [--san SAN] [--org O]
          [--ou OU] [--country C] [--state ST] [--locality L]
          [--keytype rsa|ec] [--keysize N] [--curve NAME]
          [--adcs-quirk FIELD[,FIELD...]|all] [--csr PATH] [--eku client]
      Re-issues an existing CA or server cert. Any flag not given falls
      back to the value already stored in that entity's meta.conf.
      Without --rekey the existing private key is reused; with --rekey a
      fresh keypair is generated first. --adcs-quirk (see issue-server)
      and --eku only apply to server certs. For entities created via
      sign-csr, --rekey/--cn/--san/etc. don't apply (there's no
      chainsmith-managed key or subject to change) -- pass --csr PATH to
      replace the CSR being re-signed, or omit it to just re-sign the
      existing one; --eku still applies since it's chainsmith-owned, not
      part of the CSR.

  list
      Shows every entity in the store with its type, parent, key source
      (chainsmith-managed vs externally-sourced via sign-csr), and expiry.

  show NAME
      Prints the decoded certificate for NAME (openssl x509 -text).
EOF
}

cmd_init_ca() {
  local name="" parent="" cn="" keytype="" keysize="" curve="" days=""
  local org="" ou="" country="" state="" locality=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="$2"; shift 2 ;;
      --parent) parent="$2"; shift 2 ;;
      --cn) cn="$2"; shift 2 ;;
      --keytype) keytype="$2"; shift 2 ;;
      --keysize) keysize="$2"; shift 2 ;;
      --curve) curve="$2"; shift 2 ;;
      --days) days="$2"; shift 2 ;;
      --org) org="$2"; shift 2 ;;
      --ou) ou="$2"; shift 2 ;;
      --country) country="$2"; shift 2 ;;
      --state) state="$2"; shift 2 ;;
      --locality) locality="$2"; shift 2 ;;
      *) die "unknown option '$1' for init-ca" ;;
    esac
  done
  [[ -n "$name" ]] || die "init-ca requires --name"
  [[ -e "$(entity_dir "$name")" ]] && die "'$name' already exists in the store; use reissue instead"

  CN="$cn"; prompt_if_missing CN "Common Name" ""
  [[ -n "$CN" ]] || die "Common Name is required"

  if [[ -n "$parent" ]]; then
    TYPE="intermediate"
    [[ -f "$(entity_dir "$parent")/openssl.cnf" ]] || die "parent CA '$parent' not found"
  else
    TYPE="root"
  fi
  PARENT="$parent"
  ORG="$org"; OU="$ou"; COUNTRY="$country"; STATE="$state"; LOCALITY="$locality"
  KEYTYPE="${keytype:-rsa}"
  if [[ "$KEYTYPE" == "rsa" ]]; then
    KEYSIZE="${keysize:-4096}"; CURVE=""
  else
    KEYSIZE=""; CURVE="${curve:-secp384r1}"
  fi
  if [[ "$TYPE" == "root" ]]; then
    DAYS="${days:-7300}"
  else
    DAYS="${days:-3650}"
  fi
  SAN=""
  CREATED_AT="$(now_iso)"
  REISSUE_COUNT=0
  EXTERNAL_CSR=""
  EKU=""

  mkdir_entity_skeleton "$name"
  generate_key "$name"
  render_ca_config "$name"

  local dir keyfile certfile
  dir="$(entity_dir "$name")"
  keyfile="$dir/private/$name.key.pem"
  certfile="$dir/certs/$name.cert.pem"

  if [[ "$TYPE" == "root" ]]; then
    openssl req -x509 -new -config "$dir/openssl.cnf" -key "$keyfile" \
      -days "$DAYS" -sha256 -extensions v3_ca \
      -subj "$(build_subject)" -out "$certfile"
    init_ca_bookkeeping "$name"
  else
    local csrfile parentcnf
    csrfile="$dir/csr/$name.csr.pem"
    parentcnf="$(entity_dir "$parent")/openssl.cnf"
    openssl req -new -config "$dir/openssl.cnf" -key "$keyfile" \
      -subj "$(build_subject)" -out "$csrfile"
    openssl ca -config "$parentcnf" -extensions v3_intermediate_ca \
      -days "$DAYS" -notext -batch -in "$csrfile" -out "$certfile"
    init_ca_bookkeeping "$name"
  fi

  meta_write "$name"
  build_chain "$name"
  log "created $TYPE CA '$name' -> $certfile"
}

cmd_issue_server() {
  local name="" ca="" cn="" san="" keytype="" keysize="" curve="" days=""
  local org="" ou="" country="" state="" locality="" adcs_quirk="" eku=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="$2"; shift 2 ;;
      --ca) ca="$2"; shift 2 ;;
      --cn) cn="$2"; shift 2 ;;
      --san) san="$2"; shift 2 ;;
      --keytype) keytype="$2"; shift 2 ;;
      --keysize) keysize="$2"; shift 2 ;;
      --curve) curve="$2"; shift 2 ;;
      --days) days="$2"; shift 2 ;;
      --org) org="$2"; shift 2 ;;
      --ou) ou="$2"; shift 2 ;;
      --country) country="$2"; shift 2 ;;
      --state) state="$2"; shift 2 ;;
      --locality) locality="$2"; shift 2 ;;
      --adcs-quirk) adcs_quirk="$2"; shift 2 ;;
      --eku) eku="$2"; shift 2 ;;
      *) die "unknown option '$1' for issue-server" ;;
    esac
  done
  [[ -n "$name" ]] || die "issue-server requires --name"
  if [[ -n "$adcs_quirk" ]]; then
    validate_adcs_quirk_fields "$adcs_quirk"
    require_python_cryptography
  fi
  local ext_section
  ext_section="$(resolve_eku_extension "$eku")"
  [[ -e "$(entity_dir "$name")" ]] && die "'$name' already exists in the store; use reissue instead"
  [[ -n "$ca" ]] || die "issue-server requires --ca ISSUING_CA"
  [[ -f "$(entity_dir "$ca")/openssl.cnf" ]] || die "issuing CA '$ca' not found"

  CN="$cn"; prompt_if_missing CN "Common Name" ""
  [[ -n "$CN" ]] || die "Common Name is required"
  SAN="$san"
  prompt_if_missing SAN "Subject Alternative Names (DNS:foo,IP:1.2.3.4)" "DNS:$CN"

  TYPE="server"; PARENT="$ca"
  ORG="$org"; OU="$ou"; COUNTRY="$country"; STATE="$state"; LOCALITY="$locality"
  KEYTYPE="${keytype:-rsa}"
  if [[ "$KEYTYPE" == "rsa" ]]; then
    KEYSIZE="${keysize:-2048}"; CURVE=""
  else
    KEYSIZE=""; CURVE="${curve:-prime256v1}"
  fi
  DAYS="${days:-365}"
  CREATED_AT="$(now_iso)"
  REISSUE_COUNT=0
  EXTERNAL_CSR=""
  EKU="$eku"

  mkdir_entity_skeleton "$name"
  generate_key "$name"
  render_leaf_config "$name"

  local dir keyfile certfile csrfile parentcnf
  dir="$(entity_dir "$name")"
  keyfile="$dir/private/$name.key.pem"
  certfile="$dir/certs/$name.cert.pem"
  csrfile="$dir/csr/$name.csr.pem"
  parentcnf="$(entity_dir "$ca")/openssl.cnf"

  openssl req -new -config "$dir/openssl.cnf" -key "$keyfile" \
    -subj "$(build_subject)" -out "$csrfile"
  openssl ca -config "$parentcnf" -extensions "$ext_section" \
    -days "$DAYS" -notext -batch -in "$csrfile" -out "$certfile"
  [[ -n "$adcs_quirk" ]] && apply_adcs_quirk "$name" "$adcs_quirk"

  meta_write "$name"
  build_chain "$name"
  log "issued server certificate '$name' (signed by '$ca') -> $certfile"
}

cmd_sign_csr() {
  local name="" ca="" csr="" days="" eku=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="$2"; shift 2 ;;
      --ca) ca="$2"; shift 2 ;;
      --csr) csr="$2"; shift 2 ;;
      --days) days="$2"; shift 2 ;;
      --eku) eku="$2"; shift 2 ;;
      *) die "unknown option '$1' for sign-csr" ;;
    esac
  done
  [[ -n "$name" ]] || die "sign-csr requires --name"
  [[ -e "$(entity_dir "$name")" ]] && die "'$name' already exists in the store; use reissue instead"
  [[ -n "$ca" ]] || die "sign-csr requires --ca ISSUING_CA"
  [[ -f "$(entity_dir "$ca")/openssl.cnf" ]] || die "issuing CA '$ca' not found"
  [[ -n "$csr" ]] || die "sign-csr requires --csr PATH"
  [[ -f "$csr" ]] || die "CSR file not found: '$csr'"
  local ext_section
  ext_section="$(resolve_eku_extension "$eku")"

  TYPE="server"; PARENT="$ca"
  CN=""; ORG=""; OU=""; COUNTRY=""; STATE=""; LOCALITY=""; SAN=""
  KEYTYPE=""; KEYSIZE=""; CURVE=""
  DAYS="${days:-365}"
  CREATED_AT="$(now_iso)"
  REISSUE_COUNT=0
  EXTERNAL_CSR=1
  EKU="$eku"

  mkdir_entity_skeleton "$name"
  local dir csrfile certfile parentcnf
  dir="$(entity_dir "$name")"
  csrfile="$dir/csr/$name.csr.pem"
  certfile="$dir/certs/$name.cert.pem"
  parentcnf="$(entity_dir "$ca")/openssl.cnf"
  cp "$csr" "$csrfile"

  openssl ca -config "$parentcnf" -extensions "$ext_section" \
    -days "$DAYS" -notext -batch -in "$csrfile" -out "$certfile"

  meta_write "$name"
  build_chain "$name"
  log "signed external CSR -> entity '$name' (signed by '$ca') -> $certfile"
}

cmd_reissue() {
  local name="${1:-}"; shift || true
  [[ -n "$name" ]] || die "reissue requires a NAME argument"
  meta_load "$name"
  local orig_type="$TYPE" orig_parent="$PARENT" orig_external="$EXTERNAL_CSR"
  local orig_cn="$CN" orig_org="$ORG" orig_ou="$OU"
  local orig_country="$COUNTRY" orig_state="$STATE" orig_locality="$LOCALITY"
  local rekey=0

  local days="" cn="" san="" org="" ou="" country="" state="" locality=""
  local keytype="" keysize="" curve="" adcs_quirk="" new_csr="" eku=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rekey) rekey=1; shift ;;
      --days) days="$2"; shift 2 ;;
      --cn) cn="$2"; shift 2 ;;
      --san) san="$2"; shift 2 ;;
      --org) org="$2"; shift 2 ;;
      --ou) ou="$2"; shift 2 ;;
      --country) country="$2"; shift 2 ;;
      --state) state="$2"; shift 2 ;;
      --locality) locality="$2"; shift 2 ;;
      --keytype) keytype="$2"; shift 2 ;;
      --keysize) keysize="$2"; shift 2 ;;
      --curve) curve="$2"; shift 2 ;;
      --adcs-quirk) adcs_quirk="$2"; shift 2 ;;
      --csr) new_csr="$2"; shift 2 ;;
      --eku) eku="$2"; shift 2 ;;
      *) die "unknown option '$1' for reissue" ;;
    esac
  done

  if [[ -n "$adcs_quirk" ]]; then
    [[ "$orig_type" == "server" ]] || die "--adcs-quirk only applies to server certificates ('$name' is type '$orig_type')"
    validate_adcs_quirk_fields "$adcs_quirk"
    require_python_cryptography
  fi
  if [[ -n "$eku" ]]; then
    [[ "$orig_type" == "server" ]] || die "--eku only applies to server certificates ('$name' is type '$orig_type')"
  fi

  if [[ -n "$orig_external" ]]; then
    if [[ "$rekey" -eq 1 || -n "$cn" || -n "$san" || -n "$org" || -n "$ou" || \
          -n "$country" || -n "$state" || -n "$locality" || -n "$keytype" || \
          -n "$keysize" || -n "$curve" ]]; then
      die "--rekey/--cn/--san/--org/--ou/--country/--state/--locality/--keytype/--keysize/--curve don't apply to '$name': it was created via sign-csr (subject/SAN/key come from the CSR, not chainsmith) -- use --csr PATH to replace it instead"
    fi
  elif [[ -n "$new_csr" ]]; then
    die "--csr only applies to entities created via sign-csr ('$name' has a chainsmith-managed key)"
  fi

  # meta_load already populated TYPE/PARENT/CN/... ; overlay any given flags.
  TYPE="$orig_type"; PARENT="$orig_parent"
  [[ -n "$cn" ]] && CN="$cn"
  [[ -n "$san" ]] && SAN="$san"
  [[ -n "$org" ]] && ORG="$org"
  [[ -n "$ou" ]] && OU="$ou"
  [[ -n "$country" ]] && COUNTRY="$country"
  [[ -n "$state" ]] && STATE="$state"
  [[ -n "$locality" ]] && LOCALITY="$locality"
  [[ -n "$days" ]] && DAYS="$days"
  [[ -n "$eku" ]] && EKU="$eku"
  if [[ -n "$keytype" ]]; then
    KEYTYPE="$keytype"
    if [[ "$KEYTYPE" == "rsa" ]]; then
      KEYSIZE="${keysize:-${KEYSIZE:-2048}}"; CURVE=""
    else
      KEYSIZE=""; CURVE="${curve:-${CURVE:-prime256v1}}"
    fi
  else
    [[ -n "$keysize" ]] && KEYSIZE="$keysize"
    [[ -n "$curve" ]] && CURVE="$curve"
  fi

  if [[ "$TYPE" == "root" || "$TYPE" == "intermediate" ]]; then
    if [[ "$CN" != "$orig_cn" || "$ORG" != "$orig_org" || "$OU" != "$orig_ou" || \
          "$COUNTRY" != "$orig_country" || "$STATE" != "$orig_state" || "$LOCALITY" != "$orig_locality" ]]; then
      log "WARNING: subject fields for CA '$name' changed. Certificates it" \
          "already issued carry the OLD issuer DN and will no longer chain by" \
          "name to the new certificate; reissue those children too."
    fi
  fi

  local ext_section
  ext_section="$(resolve_eku_extension "$EKU")"

  archive_entity "$name"
  REISSUE_COUNT=$((REISSUE_COUNT + 1))

  local dir keyfile certfile csrfile
  dir="$(entity_dir "$name")"
  keyfile="$dir/private/$name.key.pem"
  certfile="$dir/certs/$name.cert.pem"
  csrfile="$dir/csr/$name.csr.pem"

  if [[ -n "$orig_external" ]]; then
    if [[ -n "$new_csr" ]]; then
      [[ -f "$new_csr" ]] || die "CSR file not found: '$new_csr'"
      cp "$new_csr" "$csrfile"
    fi
    openssl ca -config "$(entity_dir "$PARENT")/openssl.cnf" \
      -extensions "$ext_section" -days "$DAYS" -notext -batch \
      -in "$csrfile" -out "$certfile"
    [[ -n "$adcs_quirk" ]] && apply_adcs_quirk "$name" "$adcs_quirk"
  else
    if [[ "$rekey" -eq 1 ]]; then
      generate_key "$name"
    fi

    case "$TYPE" in
      root)
        render_ca_config "$name"
        openssl req -x509 -new -config "$dir/openssl.cnf" -key "$keyfile" \
          -days "$DAYS" -sha256 -extensions v3_ca \
          -subj "$(build_subject)" -out "$certfile"
        if [[ "$rekey" -eq 1 ]]; then
          log "WARNING: root '$name' was rekeyed. Any intermediates previously" \
              "signed by the old root key no longer chain to it; reissue them too."
        fi
        ;;
      intermediate)
        render_ca_config "$name"
        openssl req -new -config "$dir/openssl.cnf" -key "$keyfile" \
          -subj "$(build_subject)" -out "$csrfile"
        openssl ca -config "$(entity_dir "$PARENT")/openssl.cnf" \
          -extensions v3_intermediate_ca -days "$DAYS" -notext -batch \
          -in "$csrfile" -out "$certfile"
        ;;
      server)
        render_leaf_config "$name"
        openssl req -new -config "$dir/openssl.cnf" -key "$keyfile" \
          -subj "$(build_subject)" -out "$csrfile"
        openssl ca -config "$(entity_dir "$PARENT")/openssl.cnf" \
          -extensions "$ext_section" -days "$DAYS" -notext -batch \
          -in "$csrfile" -out "$certfile"
        [[ -n "$adcs_quirk" ]] && apply_adcs_quirk "$name" "$adcs_quirk"
        ;;
      *) die "unknown entity type '$TYPE' for '$name'" ;;
    esac
  fi

  meta_write "$name"
  build_chain "$name"
  log "reissued '$name' (type=$TYPE, rekey=$rekey) -> $certfile"
}

cmd_list() {
  [[ -d "$STORE_DIR" ]] || die "store not found at $STORE_DIR"
  printf '%-20s %-12s %-20s %-10s %-9s %s\n' "NAME" "TYPE" "PARENT" "DAYS" "KEY" "EXPIRES"
  local d name expiry key_source
  for d in "$STORE_DIR"/*/; do
    [[ -f "$d/meta.conf" ]] || continue
    name="$(basename "$d")"
    meta_load "$name"
    expiry="n/a"
    if [[ -f "$d/certs/$name.cert.pem" ]]; then
      expiry="$(openssl x509 -enddate -noout -in "$d/certs/$name.cert.pem" | cut -d= -f2)"
    fi
    key_source="local"
    [[ -n "$EXTERNAL_CSR" ]] && key_source="external"
    printf '%-20s %-12s %-20s %-10s %-9s %s\n' "$name" "$TYPE" "${PARENT:--}" "$DAYS" "$key_source" "$expiry"
  done
}

cmd_show() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "show requires a NAME argument"
  local certfile
  certfile="$(entity_dir "$name")/certs/$name.cert.pem"
  [[ -f "$certfile" ]] || die "no certificate found for '$name'"
  openssl x509 -in "$certfile" -text -noout
}

main() {
  require_openssl
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || { usage; exit 1; }
  shift || true
  case "$cmd" in
    init-ca) cmd_init_ca "$@" ;;
    issue-server) cmd_issue_server "$@" ;;
    sign-csr) cmd_sign_csr "$@" ;;
    reissue) cmd_reissue "$@" ;;
    list) cmd_list "$@" ;;
    show) cmd_show "$@" ;;
    -h|--help|help) usage ;;
    *) usage; die "unknown command '$cmd'" ;;
  esac
}

main "$@"
