#!/usr/bin/env bash
# Shared helpers for chainsmith.sh. Sourced, not executed directly.

BASH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$BASH_DIR/.." && pwd)"
STORE_DIR="$ROOT_DIR/store"
TEMPLATE_DIR="$BASH_DIR/templates"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

entity_dir() { echo "$STORE_DIR/$1"; }

require_openssl() {
  command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"
}

# validate_adcs_quirk_fields RAW - dies if RAW (a comma-separated field list
# or "all") contains anything other than CN/O/OU/C/ST/L. Called before any
# CA work happens so a typo fails fast instead of wasting a serial number.
validate_adcs_quirk_fields() {
  local raw="$1" tok
  [[ -z "$raw" ]] && return 0
  [[ "${raw,,}" == "all" ]] && return 0
  IFS=',' read -ra parts <<< "$raw"
  for tok in "${parts[@]}"; do
    tok="$(echo "$tok" | xargs)"
    [[ -z "$tok" ]] && continue
    case "${tok^^}" in
      CN|O|OU|C|ST|L) ;;
      *) die "unknown --adcs-quirk field '$tok' (use CN, O, OU, C, ST, L, or 'all')" ;;
    esac
  done
}

# require_python_cryptography - lazy check, only called when --adcs-quirk is
# actually used. Every other command path in this tool stays python-free.
require_python_cryptography() {
  command -v python3 >/dev/null 2>&1 || die "--adcs-quirk requires python3 (only for this flag; no other command needs it)"
  python3 -c "import cryptography" >/dev/null 2>&1 || die "--adcs-quirk requires the python 'cryptography' package (pip install cryptography)"
}

# apply_adcs_quirk NAME FIELDS - post-processes the just-issued
# certs/<NAME>.cert.pem via lib/adcs_quirk.py: force-tags FIELDS as
# PrintableString regardless of charset (reproducing a real-world Windows
# AD CS issuance bug) and re-signs with the parent CA's key. Relies on the
# caller's PARENT global (set by cmd_issue_server/cmd_reissue) to locate the
# signing key. Also patches the CA's newcerts/<serial>.pem bookkeeping copy
# when present, so both on-disk copies stay byte-identical.
apply_adcs_quirk() {
  local name="$1" fields="$2" dir certfile parentkey serial newcerts_file
  dir="$(entity_dir "$name")"
  certfile="$dir/certs/$name.cert.pem"
  parentkey="$(entity_dir "$PARENT")/private/$PARENT.key.pem"
  local outs=("$certfile")
  if [[ -f "$(entity_dir "$PARENT")/serial.old" ]]; then
    serial="$(cat "$(entity_dir "$PARENT")/serial.old")"
    newcerts_file="$(entity_dir "$PARENT")/newcerts/$serial.pem"
    [[ -f "$newcerts_file" ]] && outs+=("$newcerts_file")
  fi
  python3 "$BASH_DIR/lib/adcs_quirk.py" "$certfile" "$parentkey" "$fields" "${outs[@]}" \
    || die "--adcs-quirk post-processing failed for '$name'"
  log "WARNING: --adcs-quirk applied to [$fields] -- '$name' is intentionally" \
      "ASN.1-nonconformant (PrintableString content violating its charset) to" \
      "reproduce a real-world CA issuance bug; expect strict parsers/browsers" \
      "to reject it."
}

# resolve_eku_extension RAW - validates RAW (empty, or a comma-separated
# list of additional EKU names to include alongside the always-present
# serverAuth; currently only "client" is supported) and echoes the
# openssl.cnf extension section name to use for -extensions when signing a
# server cert (see bash/templates/ca.cnf.tmpl: v3_server vs
# v3_server_with_client_auth).
resolve_eku_extension() {
  local raw="$1" tok
  if [[ -z "$raw" ]]; then
    echo "v3_server"
    return
  fi
  IFS=',' read -ra parts <<< "$raw"
  for tok in "${parts[@]}"; do
    tok="$(echo "$tok" | xargs)"
    [[ -z "$tok" ]] && continue
    case "${tok,,}" in
      client) ;;
      *) die "unknown --eku value '$tok' (currently supported: client)" ;;
    esac
  done
  echo "v3_server_with_client_auth"
}

# prompt_if_missing VARNAME "Prompt text" "default value"
# Reads from stdin into VARNAME if it is currently empty. When stdin isn't a
# terminal (scripted/automated invocation), silently falls back to the
# default instead of blocking on a read that can never be satisfied.
prompt_if_missing() {
  local __var="$1" __prompt="$2" __default="$3" __current
  __current="${!__var}"
  if [[ -z "$__current" ]]; then
    if [[ -t 0 ]]; then
      if [[ -n "$__default" ]]; then
        read -r -p "$__prompt [$__default]: " __current || __current=""
        __current="${__current:-$__default}"
      else
        read -r -p "$__prompt: " __current || __current=""
      fi
    else
      __current="$__default"
    fi
    printf -v "$__var" '%s' "$__current"
  fi
}

# escape_meta_value VALUE -> escapes backslash and double-quote for safe
# embedding inside a double-quoted KEY="VALUE" line.
escape_meta_value() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '%s' "$v"
}

# meta_write NAME - writes store/<NAME>/meta.conf from the current values of
# TYPE, PARENT, CN, ORG, OU, COUNTRY, STATE, LOCALITY, KEYTYPE, KEYSIZE,
# CURVE, DAYS, SAN, CREATED_AT, REISSUE_COUNT, EXTERNAL_CSR, EKU.
meta_write() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  {
    echo "NAME=\"$(escape_meta_value "$name")\""
    echo "TYPE=\"$(escape_meta_value "$TYPE")\""
    echo "PARENT=\"$(escape_meta_value "$PARENT")\""
    echo "CN=\"$(escape_meta_value "$CN")\""
    echo "ORG=\"$(escape_meta_value "$ORG")\""
    echo "OU=\"$(escape_meta_value "$OU")\""
    echo "COUNTRY=\"$(escape_meta_value "$COUNTRY")\""
    echo "STATE=\"$(escape_meta_value "$STATE")\""
    echo "LOCALITY=\"$(escape_meta_value "$LOCALITY")\""
    echo "KEYTYPE=\"$(escape_meta_value "$KEYTYPE")\""
    echo "KEYSIZE=\"$(escape_meta_value "$KEYSIZE")\""
    echo "CURVE=\"$(escape_meta_value "$CURVE")\""
    echo "DAYS=\"$(escape_meta_value "$DAYS")\""
    echo "SAN=\"$(escape_meta_value "$SAN")\""
    echo "CREATED_AT=\"$(escape_meta_value "$CREATED_AT")\""
    echo "REISSUE_COUNT=\"$(escape_meta_value "$REISSUE_COUNT")\""
    echo "EXTERNAL_CSR=\"$(escape_meta_value "$EXTERNAL_CSR")\""
    echo "EKU=\"$(escape_meta_value "$EKU")\""
  } > "$dir/meta.conf"
}

# meta_load NAME - resets and sources store/<NAME>/meta.conf, populating the
# same variable names meta_write uses.
meta_load() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  [[ -f "$dir/meta.conf" ]] || die "unknown entity '$name' (no $dir/meta.conf)"
  NAME="" TYPE="" PARENT="" CN="" ORG="" OU="" COUNTRY="" STATE="" LOCALITY=""
  KEYTYPE="" KEYSIZE="" CURVE="" DAYS="" SAN="" CREATED_AT="" REISSUE_COUNT=""
  EXTERNAL_CSR="" EKU=""
  # shellcheck disable=SC1090
  source "$dir/meta.conf"
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# archive_entity NAME - copies current private/csr/certs/openssl.cnf material
# into archive/<timestamp>/ before it gets overwritten by a reissue.
archive_entity() {
  local name="$1" dir ts dest
  dir="$(entity_dir "$name")"
  ts="$(date -u +"%Y%m%dT%H%M%SZ")"
  dest="$dir/archive/$ts"
  mkdir -p "$dest"
  for f in "private/$name.key.pem" "csr/$name.csr.pem" "certs/$name.cert.pem" \
           "certs/$name-chain.cert.pem" "openssl.cnf" "meta.conf"; do
    [[ -f "$dir/$f" ]] && cp -p "$dir/$f" "$dest/$(basename "$f")"
  done
  log "archived previous material for '$name' to $dest"
}

# build_subject -> prints an OpenSSL -subj string from CN/ORG/OU/COUNTRY/STATE/LOCALITY
build_subject() {
  local subj=""
  [[ -n "$COUNTRY" ]] && subj+="/C=$COUNTRY"
  [[ -n "$STATE" ]] && subj+="/ST=$STATE"
  [[ -n "$LOCALITY" ]] && subj+="/L=$LOCALITY"
  [[ -n "$ORG" ]] && subj+="/O=$ORG"
  [[ -n "$OU" ]] && subj+="/OU=$OU"
  subj+="/CN=$CN"
  printf '%s' "$subj"
}

# render_ca_config NAME - renders templates/ca.cnf.tmpl into store/<NAME>/openssl.cnf
render_ca_config() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  sed -e "s#__DIR__#$dir#g" \
      -e "s#__NAME__#$name#g" \
      -e "s#__DEFAULT_DAYS__#$DAYS#g" \
      "$TEMPLATE_DIR/ca.cnf.tmpl" > "$dir/openssl.cnf"
}

# san_to_alt_names "DNS:foo,DNS:bar,IP:1.2.3.4" -> prints openssl [alt_names] lines
san_to_alt_names() {
  local san="$1" entry type value dns_n=0 ip_n=0
  IFS=',' read -ra parts <<< "$san"
  for entry in "${parts[@]}"; do
    entry="$(echo "$entry" | xargs)" # trim whitespace
    [[ -z "$entry" ]] && continue
    type="${entry%%:*}"
    value="${entry#*:}"
    case "${type^^}" in
      DNS) dns_n=$((dns_n + 1)); echo "DNS.$dns_n = $value" ;;
      IP)  ip_n=$((ip_n + 1)); echo "IP.$ip_n = $value" ;;
      *) die "unsupported SAN type '$type' (use DNS: or IP:)" ;;
    esac
  done
}

# render_leaf_config NAME - renders templates/leaf.cnf.tmpl into store/<NAME>/openssl.cnf
# using SAN (falls back to "DNS:<CN>" if SAN is empty).
render_leaf_config() {
  local name="$1" dir alt_names san
  dir="$(entity_dir "$name")"
  san="$SAN"
  [[ -z "$san" ]] && san="DNS:$CN"
  alt_names="$(san_to_alt_names "$san")"
  awk -v alt="$alt_names" '{gsub(/__ALT_NAMES__/, alt); print}' \
      "$TEMPLATE_DIR/leaf.cnf.tmpl" > "$dir/openssl.cnf"
}

# init_ca_bookkeeping NAME - sets up index.txt/serial/crlnumber/newcerts for
# an entity that is itself allowed to issue certificates (root/intermediate).
init_ca_bookkeeping() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  mkdir -p "$dir/newcerts"
  : > "$dir/index.txt"
  echo "unique_subject = no" > "$dir/index.txt.attr"
  printf '1000\n' > "$dir/serial"
  printf '1000\n' > "$dir/crlnumber"
}

# generate_key NAME - writes private/<NAME>.key.pem per KEYTYPE/KEYSIZE/CURVE.
generate_key() {
  local name="$1" dir keyfile
  dir="$(entity_dir "$name")"
  keyfile="$dir/private/$name.key.pem"
  # On --rekey the file already exists chmod 400 from its previous
  # generation; openssl can't open it for writing until we restore write
  # permission (removing it outright would also work, but this preserves
  # the file's identity/inode for anything watching it).
  [[ -e "$keyfile" ]] && chmod 600 "$keyfile"
  case "$KEYTYPE" in
    rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEYSIZE" -out "$keyfile" 2>/dev/null ;;
    ec)  openssl ecparam -name "$CURVE" -genkey -noout -out "$keyfile" ;;
    *) die "unsupported keytype '$KEYTYPE' (use rsa or ec)" ;;
  esac
  chmod 400 "$keyfile"
}

mkdir_entity_skeleton() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  mkdir -p "$dir/private" "$dir/csr" "$dir/certs" "$dir/archive"
  chmod 700 "$dir/private"
}

# parent_of NAME - prints NAME's PARENT field without touching the caller's
# global TYPE/CN/... state (unlike meta_load, safe to call mid-command).
parent_of() {
  local name="$1" dir
  dir="$(entity_dir "$name")"
  ( PARENT=""; source "$dir/meta.conf" 2>/dev/null; printf '%s' "$PARENT" )
}

# build_chain NAME - writes certs/<NAME>-chain.cert.pem by walking PARENT links.
build_chain() {
  local name="$1" dir out cur
  dir="$(entity_dir "$name")"
  out="$dir/certs/$name-chain.cert.pem"
  : > "$out"
  cur="$name"
  while [[ -n "$cur" ]]; do
    cat "$(entity_dir "$cur")/certs/$cur.cert.pem" >> "$out"
    cur="$(parent_of "$cur")"
  done
}
