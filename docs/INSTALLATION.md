# Guide d'Installation - Système PKI PST

Guide complet pour installer et configurer le système PKI avec HSM embarqué.

## Architecture

```
┌─────────────────────────────────────┐
│     Raspberry Pi (HSM)              │
│  ┌──────────────────────────────┐   │
│  │  Bibliothèque PKCS#11        │   │
│  │  - Crypto Ops (RSA, ECDSA)   │   │
│  │  - Stockage sécurisé         │   │
│  │  - Gestion sessions/PIN      │   │
│  └──────────────────────────────┘   │
│  ┌──────────────────────────────┐   │
│  │  Serveur Réseau (TLS)        │   │
│  │  - Port 11111                │   │
│  │  - Ethernet uniquement       │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
              ↕ TCP/TLS
┌─────────────────────────────────────┐
│   Poste Client (PC/Mac/Linux)       │
│  ┌──────────────────────────────┐   │
│  │  Application Cliente          │   │
│  │  - Interface CLI/GUI         │   │
│  │  - Client PKCS#11            │   │
│  │  - Gestion clés/certs        │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
```

## Partie 1: Installation HSM (Raspberry Pi)

### Prérequis Matériel
- Raspberry Pi 4 (4GB RAM minimum)
- Carte SD 16GB minimum
- Connexion Ethernet
- Alimentation

### Installation OS

1. **Télécharger Raspberry Pi OS Lite (64-bit)**
   ```bash
   # Utiliser Raspberry Pi Imager
   # Choisir: Raspberry Pi OS Lite (64-bit)
   # Configurer SSH lors de l'écriture
   ```

2. **Premier démarrage**
   ```bash
   # Se connecter via SSH
   ssh pi@raspberrypi.local
   # Mot de passe par défaut: raspberry

   # Changer le mot de passe
   passwd

   # Mettre à jour le système
   sudo apt-get update
   sudo apt-get upgrade -y
   ```

### Installation des Dépendances

```bash
# Outils de compilation
sudo apt-get install -y build-essential git cmake

# OpenSSL (crypto)
sudo apt-get install -y libssl-dev

# Bibliothèques système
sudo apt-get install -y libpthread-stubs0-dev

# Outils réseau
sudo apt-get install -y net-tools iptables
```

### Compilation HSM

```bash
# Cloner le repository
git clone https://github.com/votre-org/PST_BOITIER_PKI.git
cd PST_BOITIER_PKI/hsm

# Compiler
make clean
make

# Tester
make test

# Installer
sudo make install
```

### Configuration Sécurité

```bash
# Créer répertoire de stockage
sudo mkdir -p /var/lib/hsm/keys
sudo chmod 700 /var/lib/hsm
sudo chown pi:pi /var/lib/hsm

# Désactiver services non nécessaires
sudo systemctl disable bluetooth
sudo systemctl disable wifi

# Configurer firewall (uniquement port 11111)
sudo iptables -A INPUT -p tcp --dport 11111 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -j DROP
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### Configuration Réseau Statique

```bash
# Éditer /etc/dhcpcd.conf
sudo nano /etc/dhcpcd.conf

# Ajouter:
interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1

# Redémarrer
sudo reboot
```

### Démarrage Automatique

```bash
# Créer service systemd
sudo nano /etc/systemd/system/pst-hsm.service
```

Contenu du fichier:
```ini
[Unit]
Description=PST HSM Network Server
After=network.target

[Service]
Type=simple
User=pi
ExecStart=/usr/local/bin/pst-hsm-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activer le service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable pst-hsm
sudo systemctl start pst-hsm
sudo systemctl status pst-hsm
```

## Partie 2: Installation Client

### Prérequis
- Node.js 18+
- npm ou yarn
- Connexion réseau au HSM

### Installation

```bash
cd PST_BOITIER_PKI/client

# Installer dépendances
npm install

# Configuration
cp .env.example .env
nano .env
```

Contenu `.env`:
```bash
HSM_HOST=192.168.1.100
HSM_PORT=11111
HSM_PIN=user1234
HSM_SLOT=0
LOG_LEVEL=info
```

### Test de Connexion

```bash
# Tester la connexion au HSM
npm start info

# Si succès, vous devriez voir:
# ✓ Connected to HSM
# Library Version: 2.40
# Token Label: PST HSM Token
```

## Partie 3: Configuration Initiale

### Initialiser le Token

```bash
# Sur le Raspberry Pi ou via client
cd /home/pi/PST_BOITIER_PKI/hsm
./bin/test_basic

# Ou via le client
npm start -- initialize-token --so-pin "1234567890" --label "Mon HSM"
```

### Créer PIN Utilisateur

```bash
npm start -- init-user-pin --so-pin "1234567890" --user-pin "user1234"
```

### Générer Premières Clés

```bash
# Clé RSA pour signature
npm start generate-rsa -- --bits 2048 --label "SignatureKey" --token

# Clé EC pour authentification
npm start generate-ec -- --curve P-256 --label "AuthKey" --token

# Vérifier
npm start list-keys
```

## Partie 4: Tests de Fonctionnement

### Test Signature RSA

```bash
# Créer fichier test
echo "Document de test" > test.txt

# Signer
npm start sign -- --key "SignatureKey" --file test.txt

# Vérifier
npm start verify -- --key "SignatureKey" --file test.txt --signature test.txt.sig
```

### Test Performance

```bash
# Générer clé RSA-2048 (devrait prendre ~2 secondes)
time npm start generate-rsa -- --bits 2048 --label "PerfTest"

# Signer 100 fois
for i in {1..100}; do
  npm start sign -- --key "PerfTest" --file test.txt --output test_$i.sig
done
```

## Partie 5: Sécurisation Production

### Hardening Raspberry Pi

```bash
# Désactiver login root
sudo passwd -l root

# Configurer fail2ban
sudo apt-get install fail2ban
sudo systemctl enable fail2ban

# Mise à jour automatique
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Audit de sécurité
sudo apt-get install lynis
sudo lynis audit system
```

### Chiffrement Stockage

**IMPORTANT**: Le stockage actuel n'est PAS chiffré. Pour production:

```bash
# Option 1: Utiliser LUKS pour chiffrer /var/lib/hsm
sudo cryptsetup luksFormat /dev/mmcblk0p3
sudo cryptsetup luksOpen /dev/mmcblk0p3 hsm_storage

# Option 2: Implémenter chiffrement au niveau application
# (Nécessite modification du code dans storage.c)
```

### TLS Mutuel

Pour activer TLS mutuel (actuellement non implémenté):

1. Générer certificats
```bash
# Autorité de certification
openssl req -new -x509 -days 3650 -keyout ca-key.pem -out ca-cert.pem

# Certificat serveur (HSM)
openssl req -new -keyout server-key.pem -out server-req.pem
openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem

# Certificat client
openssl req -new -keyout client-key.pem -out client-req.pem
openssl x509 -req -in client-req.pem -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 02 -out client-cert.pem
```

2. Modifier le code pour utiliser OpenSSL/mbedTLS

## Partie 6: Dépannage

### HSM ne démarre pas

```bash
# Vérifier logs
sudo journalctl -u pst-hsm -f

# Vérifier permissions
ls -la /var/lib/hsm
# Doit être: drwx------ pi pi

# Tester manuellement
/usr/local/bin/pst-hsm-server
```

### Client ne peut pas se connecter

```bash
# Ping HSM
ping 192.168.1.100

# Vérifier port ouvert
nc -zv 192.168.1.100 11111

# Vérifier firewall
sudo iptables -L -n
```

### Erreurs de signature

```bash
# Vérifier clés
npm start list-keys

# Vérifier logs HSM
ssh pi@192.168.1.100
tail -f /var/log/syslog | grep hsm
```

### Performance dégradée

```bash
# Vérifier CPU/RAM
top

# Vérifier température
vcgencmd measure_temp

# Si >80°C, ajouter refroidissement
```

## Partie 7: Maintenance

### Backup

```bash
# Backup complet HSM
sudo tar czf hsm-backup-$(date +%Y%m%d).tar.gz /var/lib/hsm

# Restauration
sudo tar xzf hsm-backup-YYYYMMDD.tar.gz -C /
```

### Mise à Jour

```bash
# Mise à jour bibliothèque
cd PST_BOITIER_PKI/hsm
git pull
make clean
make
sudo make install
sudo systemctl restart pst-hsm

# Mise à jour client
cd PST_BOITIER_PKI/client
git pull
npm install
```

### Monitoring

```bash
# Installer Prometheus node exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-arm64.tar.gz
tar xzf node_exporter-1.6.1.linux-arm64.tar.gz
sudo mv node_exporter-1.6.1.linux-arm64/node_exporter /usr/local/bin/
sudo systemctl enable node_exporter
```

## Ressources

- Documentation PKCS#11: https://docs.oasis-open.org/pkcs11/
- OpenSSL: https://www.openssl.org/docs/
- Raspberry Pi: https://www.raspberrypi.org/documentation/

## Support

Pour toute question:
- Issues GitHub: https://github.com/votre-org/PST_BOITIER_PKI/issues
- Documentation: `/docs`
- Email: support@pst-systems.com
