#!/bin/bash

# Script de build complet du projet
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "PST PKI HSM - Build Complet"
echo "=========================================="
echo ""

# Build serveur HSM
echo "[1/3] Build serveur HSM..."
docker-compose build pki-hsm
echo "✓ Serveur HSM build"
echo ""

# Build client
echo "[2/3] Build client..."
docker-compose build pki-client-dev
echo "✓ Client build"
echo ""

# Générer certificats si nécessaire
echo "[3/3] Vérification certificats TLS..."
if [ ! -f "certs/ca.crt" ]; then
    ./certs/generate-certs.sh
else
    echo "✓ Certificats TLS déjà générés"
fi

echo ""
echo "=========================================="
echo "✓ Build complet terminé!"
echo "=========================================="
echo ""
echo "Prochaines étapes:"
echo "  ./scripts/start-dev.sh    # Démarrer l'environnement"
echo "  docker-compose up -d      # Alternative directe"
echo ""
