#!/bin/bash

#
# Script de Déploiement Automatique - PST HSM
# Usage: ./deploy_hsm.sh [raspberry-pi-ip]
#

set -e

HSM_IP="${1:-raspberrypi.local}"
HSM_USER="${2:-pi}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "======================================"
echo "PST HSM - Déploiement Automatique"
echo "======================================"
echo ""
echo "Cible: $HSM_USER@$HSM_IP"
echo "Source: $PROJECT_DIR"
echo ""

# Vérifier connexion SSH
echo "[1/8] Vérification de la connexion SSH..."
if ! ssh -o ConnectTimeout=5 $HSM_USER@$HSM_IP "echo 'SSH OK'" > /dev/null 2>&1; then
    echo "❌ Erreur: Impossible de se connecter à $HSM_USER@$HSM_IP"
    echo "Vérifiez que:"
    echo "  - Le Raspberry Pi est allumé et connecté"
    echo "  - SSH est activé"
    echo "  - L'adresse IP est correcte"
    exit 1
fi
echo "✓ Connexion SSH établie"
echo ""

# Installation des dépendances
echo "[2/8] Installation des dépendances..."
ssh $HSM_USER@$HSM_IP << 'EOF'
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev git
EOF
echo "✓ Dépendances installées"
echo ""

# Création des répertoires
echo "[3/8] Création des répertoires..."
ssh $HSM_USER@$HSM_IP << 'EOF'
mkdir -p ~/pst-hsm
sudo mkdir -p /var/lib/hsm/keys
sudo chown -R $USER:$USER /var/lib/hsm
chmod 700 /var/lib/hsm
EOF
echo "✓ Répertoires créés"
echo ""

# Copie des fichiers
echo "[4/8] Copie des fichiers sources..."
rsync -avz --exclude='.git' --exclude='build' --exclude='lib' \
    $PROJECT_DIR/hsm/ $HSM_USER@$HSM_IP:~/pst-hsm/
echo "✓ Fichiers copiés"
echo ""

# Compilation
echo "[5/8] Compilation du HSM..."
ssh $HSM_USER@$HSM_IP << 'EOF'
cd ~/pst-hsm
make clean
make
echo "✓ Compilation réussie"
EOF
echo ""

# Installation
echo "[6/8] Installation système..."
ssh $HSM_USER@$HSM_IP << 'EOF'
cd ~/pst-hsm
sudo make install
sudo ldconfig
EOF
echo "✓ Installation terminée"
echo ""

# Configuration du service systemd
echo "[7/8] Configuration du service..."
ssh $HSM_USER@$HSM_IP << 'EOF'
cat << 'UNIT' | sudo tee /etc/systemd/system/pst-hsm.service > /dev/null
[Unit]
Description=PST HSM Network Server
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/pst-hsm
ExecStart=/usr/local/lib/pkcs11/pst-hsm-server
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable pst-hsm
EOF
echo "✓ Service configuré"
echo ""

# Démarrage du service
echo "[8/8] Démarrage du service..."
ssh $HSM_USER@$HSM_IP << 'EOF'
sudo systemctl restart pst-hsm
sleep 2
sudo systemctl status pst-hsm --no-pager
EOF
echo "✓ Service démarré"
echo ""

echo "======================================"
echo "✓ Déploiement terminé avec succès!"
echo "======================================"
echo ""
echo "Prochaines étapes:"
echo "  1. Initialiser le token:"
echo "     ssh $HSM_USER@$HSM_IP"
echo "     cd ~/pst-hsm"
echo "     LD_LIBRARY_PATH=./lib ./bin/test_basic"
echo ""
echo "  2. Vérifier les logs:"
echo "     ssh $HSM_USER@$HSM_IP"
echo "     sudo journalctl -u pst-hsm -f"
echo ""
echo "  3. Tester depuis le client:"
echo "     cd client"
echo "     HSM_HOST=$HSM_IP npm start info"
echo ""
