#!/bin/bash
# Only the dedicated, unfunded simulation internal node. Keep keys and CA local.
set -euo pipefail
umask 077
root=/var/lib/abandon-simulation/ln-internal/signet
for dir in "$root" "$root/hold"; do
    test -s "$dir/ca.pem"; test -s "$dir/ca-key.pem"; test -s "$dir/server-key.pem"
    if openssl verify -CAfile "$dir/ca.pem" -verify_ip 170.75.173.102 "$dir/server.pem" >/dev/null 2>&1; then continue; fi
    tmp=$(mktemp -d "$dir/sim-tls.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    openssl req -new -key "$dir/server-key.pem" -out "$tmp/server.csr" -subj /CN=localhost
    cat > "$tmp/extensions" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:170.75.173.102
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
    openssl x509 -req -in "$tmp/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" -set_serial "0x$(openssl rand -hex 16)" -days 365 -sha256 -extfile "$tmp/extensions" -out "$tmp/server.pem"
    openssl verify -CAfile "$dir/ca.pem" "$tmp/server.pem"
    install -m 600 "$tmp/server.pem" "$dir/server.pem"
    openssl verify -CAfile "$dir/ca.pem" -verify_ip 170.75.173.102 "$dir/server.pem"
    openssl x509 -in "$dir/server.pem" -noout -fingerprint -sha256
    rm -rf "$tmp"; trap - EXIT
done
