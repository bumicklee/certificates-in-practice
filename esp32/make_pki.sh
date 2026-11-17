#!/usr/bin/env bash
# make_pki.sh - course-only demo PKI for cert-lab (NEVER use these keys for anything real)
#
# usage: ./make_pki.sh <PC_LAN_IP> [--force]
#   e.g. ./make_pki.sh <PC_LAN_IP>   (your PC's private IP)
#
# Creates ./demo-pki/ :
#   root/ inter/            lab root CA and intermediate CA (EC P-256)
#   server/                 server cert, SAN = <PC_LAN_IP> + DNS:cert-lab.local  (good)
#   wrongname/              server cert issued by the same lab chain, SAN = another name (case "wrong hostname")
#   rogue/                  a second, unknown root + server cert (case "unknown root")
#   device/                 mTLS client certs: dev-001 (valid), dev-expired (expired)
#   ota/                    lab_ota_key.pem (signs firmware), other_key.pem (forger's key)
#   embed/                  flat copies the firmware embeds at build time
set -euo pipefail

IP="${1:-}"
[[ -n "$IP" ]] || { echo "usage: $0 <PC_LAN_IP> [--force]" >&2; exit 1; }
[[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not an IPv4 address: $IP" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
PKI="$HERE/demo-pki"
if [[ -d "$PKI" ]]; then
  if [[ "${2:-}" == "--force" ]]; then rm -rf "$PKI"; else
    echo "$PKI already exists. Use --force to regenerate (firmware must be rebuilt afterwards)." >&2; exit 1; fi
fi
mkdir -p "$PKI"/{root,inter,server,wrongname,rogue,device,ota,embed}
cd "$PKI"

START="$(date -u -v-1d +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '-1 day' +%Y%m%d%H%M%SZ)"
END="$(date -u -v+825d +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '+825 days' +%Y%m%d%H%M%SZ)"
CA_END="$(date -u -v+3650d +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d '+3650 days' +%Y%m%d%H%M%SZ)"

# --- minimal 'openssl ca' config (one DB per issuer, selected via CA_DIR) ---
cat > ca.cnf <<'CNF'
[ca]
default_ca = CA_default
[CA_default]
database        = $ENV::CA_DIR/index.txt
serial          = $ENV::CA_DIR/serial
new_certs_dir   = $ENV::CA_DIR
default_md      = sha256
policy          = policy_any
unique_subject  = no
copy_extensions = none
[policy_any]
organizationName = optional
commonName       = supplied
[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
CNF

cat > ext.cnf <<CNF
[root_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[inter_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[server_good]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:$IP,DNS:cert-lab.local
[server_wrongname]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:wrong-name.example,IP:192.0.2.77
[client]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
CNF

newkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
initdb() { : > "$1/index.txt"; echo 1000 > "$1/serial"; }

# sign <issuer_dir> <issuer_crt> <issuer_key> <csr> <out_crt> <ext_section> <startdate> <enddate>
sign() {
  CA_DIR="$1" openssl ca -batch -config ca.cnf -cert "$2" -keyfile "$3" -in "$4" -out "$5" \
    -extfile ext.cnf -extensions "$6" -startdate "$7" -enddate "$8" -notext 2>/dev/null
}
# mkcert <dir> <name> <CN> <issuer_dir> <issuer_crt> <issuer_key> <ext> [start] [end]
mkcert() {
  newkey "$1/$2.key"
  openssl req -new -key "$1/$2.key" -subj "/O=CertLab DEMO ONLY/CN=$3" -out "$1/$2.csr"
  sign "$4" "$5" "$6" "$1/$2.csr" "$1/$2.crt" "$7" "${8:-$START}" "${9:-$END}"
  rm -f "$1/$2.csr"
}

# --- lab root + intermediate ---
initdb root; newkey root/lab-root.key
openssl req -new -key root/lab-root.key -subj "/O=CertLab DEMO ONLY/CN=CertLab Demo Root CA" -out root/root.csr
CA_DIR=root openssl ca -batch -config ca.cnf -selfsign -keyfile root/lab-root.key -in root/root.csr \
  -out root/lab-root.crt -extfile ext.cnf -extensions root_ca -startdate "$START" -enddate "$CA_END" -notext 2>/dev/null
rm -f root/root.csr
initdb inter
mkcert inter lab-inter "CertLab Demo Intermediate CA" root root/lab-root.crt root/lab-root.key inter_ca "$START" "$CA_END"

# --- server certs (good / wrong name), both from the lab chain; served as leaf + intermediate ---
mkcert server server "cert-lab.local" inter inter/lab-inter.crt inter/lab-inter.key server_good
cat server/server.crt inter/lab-inter.crt > server/server-chain.crt
mkcert wrongname wrongname "wrong-name.example" inter inter/lab-inter.crt inter/lab-inter.key server_wrongname
cat wrongname/wrongname.crt inter/lab-inter.crt > wrongname/wrongname-chain.crt

# --- rogue root (board does not trust it) ---
mkdir -p rogue/ca; initdb rogue/ca; newkey rogue/rogue-root.key
openssl req -new -key rogue/rogue-root.key -subj "/O=Rogue DEMO ONLY/CN=Rogue Demo Root CA" -out rogue/r.csr
CA_DIR=rogue/ca openssl ca -batch -config ca.cnf -selfsign -keyfile rogue/rogue-root.key -in rogue/r.csr \
  -out rogue/rogue-root.crt -extfile ext.cnf -extensions root_ca -startdate "$START" -enddate "$CA_END" -notext 2>/dev/null
rm -f rogue/r.csr
mkcert rogue rogue-server "cert-lab.local" rogue/ca rogue/rogue-root.crt rogue/rogue-root.key server_good
cp rogue/rogue-server.crt rogue/rogue-server-chain.crt

# --- device (client) certs for mTLS ---
mkcert device dev-001 "dev-001" inter inter/lab-inter.crt inter/lab-inter.key client
cat device/dev-001.crt inter/lab-inter.crt > device/dev-001-chain.crt
mkcert device dev-expired "dev-expired" inter inter/lab-inter.crt inter/lab-inter.key client 20240101000000Z 20240201000000Z
cat device/dev-expired.crt inter/lab-inter.crt > device/dev-expired-chain.crt

# --- broker CA bundle (root + intermediate) ---
cat root/lab-root.crt inter/lab-inter.crt > ca-chain.pem

# --- firmware signing keys (ECDSA P-256 / Secure Boot v2 format; course-only) ---
ESPSECURE="${ESPSECURE:-}"
if [[ -z "$ESPSECURE" ]]; then
  if command -v espsecure.py >/dev/null; then ESPSECURE=espsecure.py
  elif command -v espsecure >/dev/null; then ESPSECURE=espsecure
  else echo "[WARN] espsecure not found: source ~/esp/esp-idf-v5.5/export.sh first, then rerun with --force" >&2; fi
fi
if [[ -n "$ESPSECURE" ]]; then
  "$ESPSECURE" generate_signing_key --version 2 --scheme ecdsa256 ota/lab_ota_key.pem >/dev/null 2>&1 \
    || "$ESPSECURE" generate-signing-key --version 2 --scheme ecdsa256 ota/lab_ota_key.pem
  "$ESPSECURE" generate_signing_key --version 2 --scheme ecdsa256 ota/other_key.pem >/dev/null 2>&1 \
    || "$ESPSECURE" generate-signing-key --version 2 --scheme ecdsa256 ota/other_key.pem
fi

# --- flat copies embedded by the firmware ---
cp root/lab-root.crt            embed/lab_root.crt
cp rogue/rogue-root.crt         embed/rogue_root.crt
cp device/dev-001-chain.crt     embed/client.crt
cp device/dev-001.key           embed/client.key
cp device/dev-expired-chain.crt embed/expired_client.crt
cp device/dev-expired.key       embed/expired_client.key
echo "$IP" > embed/LAN_IP.txt

chmod 600 */*.key ota/*.pem 2>/dev/null || true
rm -f root/*.pem inter/*.pem 2>/dev/null || true
echo "[OK] demo PKI created in $PKI (server SAN = $IP). Course-only keys: do not reuse."
