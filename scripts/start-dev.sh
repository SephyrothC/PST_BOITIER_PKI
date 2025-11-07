#!/bin/bash

# Script de démarrage de l'environnement de développement Docker
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "PST PKI HSM - Démarrage Environnement Dev"
echo "=========================================="
echo ""

# Vérifier que Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé!"
    echo "   Installez Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose n'est pas installé!"
    echo "   Installez Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✓ Docker et Docker Compose sont installés"
echo ""

# Générer les certificats TLS si nécessaire
if [ ! -f "certs/ca.crt" ]; then
    echo "📜 Génération des certificats TLS..."
    ./certs/generate-certs.sh
    echo ""
fi

# Créer le fichier .env si nécessaire
if [ ! -f ".env" ]; then
    echo "⚙️  Création du fichier .env..."
    cat > .env << EOF
# Configuration HSM
HSM_PIN=changeme123456
LOG_LEVEL=INFO

# Configuration réseau
HSM_PORT=8443
CLIENT_PORT=3000

# Mode développement
NODE_ENV=development
EOF
    echo "✓ Fichier .env créé"
    echo ""
fi

# Nettoyer les anciens conteneurs si demandé
if [ "$1" == "--clean" ]; then
    echo "🧹 Nettoyage des conteneurs existants..."
    docker-compose down -v
    echo ""
fi

# Builder les images
echo "🔨 Construction des images Docker..."
docker-compose build

echo ""
echo "🚀 Démarrage des conteneurs..."
docker-compose up -d

echo ""
echo "⏳ Attente du démarrage du serveur HSM..."
sleep 5

# Vérifier que le serveur HSM est démarré
if docker-compose ps | grep -q "pki-hsm.*Up"; then
    echo "✓ Serveur HSM démarré"
else
    echo "❌ Erreur: Le serveur HSM n'a pas démarré correctement"
    echo ""
    echo "Logs du serveur HSM:"
    docker-compose logs pki-hsm
    exit 1
fi

echo ""
echo "=========================================="
echo "✓ Environnement de développement prêt!"
echo "=========================================="
echo ""
echo "Services démarrés:"
echo "  🔐 HSM Server:  https://localhost:8443"
echo "  💻 Client Dev:  http://localhost:3000"
echo ""
echo "Commandes utiles:"
echo "  docker-compose logs -f pki-hsm    # Voir les logs HSM"
echo "  docker-compose logs -f pki-client-dev # Voir les logs client"
echo "  docker-compose exec pki-hsm /bin/bash  # Shell dans HSM"
echo "  ./scripts/stop-dev.sh              # Arrêter l'environnement"
echo ""
echo "Configuration:"
echo "  Certificats TLS: ./certs/"
echo "  Config HSM: ./hsm-server/config/"
echo "  PIN HSM: ${HSM_PIN:-changeme123456}"
echo ""
