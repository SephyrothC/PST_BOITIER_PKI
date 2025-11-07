#!/bin/bash

# Script de génération des certificats TLS pour mTLS
# Utilisé par le serveur HSM et le client

set -e

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CERT_DIR"

echo "========================================"
echo "Génération des certificats TLS"
echo "========================================"
echo ""

# Configuration
COUNTRY="FR"
STATE="IDF"
CITY="Paris"
ORG="PST Cryptographic Systems"
OU="PKI HSM"
VALIDITY_DAYS=3650  # 10 ans

# Nettoyage
rm -f *.pem *.crt *.key *.csr *.srl

echo "[1/5] Génération de l'autorité de certification (CA)..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $VALIDITY_DAYS -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=PST PKI Root CA"
echo "✓ CA générée: ca.crt"

echo ""
echo "[2/5] Génération du certificat serveur (HSM)..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=pki-hsm"

# Extensions pour le certificat serveur
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = pki-hsm
DNS.2 = localhost
IP.1 = 172.20.0.10
IP.2 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days $VALIDITY_DAYS \
    -extfile server.ext

rm server.csr server.ext
echo "✓ Certificat serveur généré: server.crt"

echo ""
echo "[3/5] Génération du certificat client..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=pki-client"

# Extensions pour le certificat client
cat > client.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = pki-client
DNS.2 = localhost
IP.1 = 172.20.0.20
IP.2 = 127.0.0.1
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days $VALIDITY_DAYS \
    -extfile client.ext

rm client.csr client.ext
echo "✓ Certificat client généré: client.crt"

echo ""
echo "[4/5] Génération du certificat client admin..."
openssl genrsa -out admin.key 2048
openssl req -new -key admin.key -out admin.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=pki-admin"

cat > admin.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out admin.crt -days $VALIDITY_DAYS \
    -extfile admin.ext

rm admin.csr admin.ext
echo "✓ Certificat admin généré: admin.crt"

echo ""
echo "[5/5] Vérification des certificats..."
echo "Vérification serveur:"
openssl verify -CAfile ca.crt server.crt
echo "Vérification client:"
openssl verify -CAfile ca.crt client.crt
echo "Vérification admin:"
openssl verify -CAfile ca.crt admin.crt

echo ""
echo "✓ Tous les certificats ont été générés avec succès!"
echo ""
echo "Fichiers créés:"
echo "  ca.crt, ca.key       - Autorité de certification"
echo "  server.crt, server.key - Certificat serveur HSM"
echo "  client.crt, client.key - Certificat client"
echo "  admin.crt, admin.key   - Certificat admin"
echo ""
echo "⚠️  IMPORTANT: Protégez les clés privées (*.key)!"
echo "    chmod 600 *.key"

# Sécuriser les clés privées
chmod 600 *.key
chmod 644 *.crt

echo ""
echo "Affichage des informations des certificats:"
echo "==========================================="
echo ""
echo "CA:"
openssl x509 -in ca.crt -noout -subject -dates

echo ""
echo "Serveur:"
openssl x509 -in server.crt -noout -subject -dates -ext subjectAltName

echo ""
echo "Client:"
openssl x509 -in client.crt -noout -subject -dates

echo ""
echo "========================================"
echo "Génération terminée!"
echo "========================================"
