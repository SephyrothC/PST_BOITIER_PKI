#!/bin/bash

# Script d'arrêt de l'environnement de développement Docker
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "PST PKI HSM - Arrêt Environnement Dev"
echo "=========================================="
echo ""

echo "🛑 Arrêt des conteneurs..."
docker-compose down

if [ "$1" == "--clean" ]; then
    echo ""
    echo "🧹 Suppression des volumes (clés effacées)..."
    docker-compose down -v
    echo "✓ Volumes supprimés"
fi

echo ""
echo "✓ Environnement arrêté"
echo ""

if [ "$1" != "--clean" ]; then
    echo "💡 Les données persistantes sont conservées"
    echo "   Pour tout supprimer: ./scripts/stop-dev.sh --clean"
    echo ""
fi
