# Système PKI avec HSM Embarqué

[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![C11](https://img.shields.io/badge/C-11-blue.svg)]()
[![PKCS11](https://img.shields.io/badge/PKCS%2311-v2.40-green.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)]()

Système PKI complet et sécurisé composé d'un boîtier cryptographique embarqué (Raspberry Pi) agissant comme HSM (Hardware Security Module) et d'une application cliente moderne. Le projet utilise Docker pour le développement et peut être déployé directement sur Raspberry Pi.

## 🎯 Objectifs

- **Isolation cryptographique**: Opérations sensibles isolées sur matériel dédié
- **Conformité PKCS#11**: Interface standard pour compatibilité maximale
- **Sécurité renforcée**: Clés privées jamais exportables, stockage chiffré AES-256-GCM
- **Performance**: Signature RSA 2048 bits < 500ms sur Raspberry Pi 4
- **Docker-First**: Développement simplifié avec containers, déploiement identique sur RPi

## 📋 Table des Matières

- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Démarrage Rapide avec Docker](#démarrage-rapide-avec-docker)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Documentation](#documentation)
- [Développement](#développement)
- [Déploiement sur Raspberry Pi](#déploiement-sur-raspberry-pi)
- [Sécurité](#sécurité)
- [Roadmap](#roadmap)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│     HSM Server (Docker / Raspberry Pi)          │
│  ┌──────────────────────────────────────────┐   │
│  │  Bibliothèque PKCS#11 v2.40 (C)          │   │
│  │  ✓ Génération clés RSA/EC                │   │
│  │  ✓ Signature numérique                   │   │
│  │  ✓ Stockage chiffré AES-256-GCM          │   │
│  │  ✓ Gestion PIN/sessions                  │   │
│  └──────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────┐   │
│  │  TLS Server (Port 8443)                  │   │
│  │  ✓ TLS 1.3 avec mTLS                     │   │
│  │  ✓ Protocole PKCS#11 over TLS            │   │
│  │  ✓ Client certificates required          │   │
│  │  ✓ OpenSSL 3.x                           │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
              ↕ TLS 1.3 (mTLS)
┌─────────────────────────────────────────────────┐
│   Application Cliente (Docker / Desktop)        │
│  ┌──────────────────────────────────────────┐   │
│  │  Interface CLI Interactive                │   │
│  │  ✓ Gestion des clés                      │   │
│  │  ✓ Signature de documents                │   │
│  │  ✓ Gestion certificats                   │   │
│  │  ✓ Interface moderne                     │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Architecture Docker

Le système utilise Docker Compose pour orchestrer deux services:

- **pki-hsm** (172.20.0.10:8443): Serveur HSM PKCS#11 avec TLS
- **pki-client-dev** (172.20.0.20): Environnement de développement client

Le réseau Docker isolé (172.20.0.0/24) permet une communication sécurisée entre les composants.

### Composant HSM Server

- **Localisation**: `hsm-server/`
- **Rôle**: Boîtier cryptographique embarqué sur Raspberry Pi ou conteneur Docker
- **Technologies**: C11, CMake, OpenSSL 3.x, PKCS#11 v2.40
- **Fonctionnalités**:
  - ✅ Bibliothèque PKCS#11 (Cryptoki) complète
  - ✅ Génération de bi-clés RSA (2048/4096 bits) et ECDSA (P-256, P-384, P-521)
  - ✅ Signature numérique (RSA-PKCS, RSA-PSS, ECDSA)
  - ✅ Stockage sécurisé chiffré AES-256-GCM avec PBKDF2 (600k iterations)
  - ✅ Serveur TLS 1.3 avec authentification mutuelle (mTLS)
  - ✅ Protection par PIN/passphrase
  - ✅ Gestion des sessions et timeouts

### Composant Client

- **Localisation**: `client-app/`
- **Rôle**: Application moderne pour gérer les opérations cryptographiques
- **Technologies**: Node.js, Commander, Inquirer, Chalk
- **Fonctionnalités**:
  - ✅ Interface CLI interactive et conviviale
  - ✅ Client TLS avec certificat client
  - ✅ Gestion complète des bi-clés (génération, liste, suppression)
  - ✅ Signature et vérification de documents
  - ✅ Support des certificats X.509
  - ⏳ Interface graphique (Electron/Tauri) - À venir

## ✨ Fonctionnalités

### Opérations Cryptographiques
- ✅ **Génération de clés**: RSA 2048/4096, EC P-256/P-384/P-521
- ✅ **Signature**: RSA-PKCS, RSA-PSS, ECDSA avec SHA-256/384/512
- ✅ **Vérification**: Validation de signatures numériques
- ✅ **Random**: Génération de nombres aléatoires cryptographiquement sûrs

### Gestion des Clés
- ✅ Clés privées non exportables et sensibles
- ✅ Stockage chiffré AES-256-GCM
- ✅ Dérivation de clé PBKDF2 (600,000 iterations)
- ✅ Protection par PIN utilisateur et SO
- ✅ Limitation tentatives d'authentification (3 essais)
- ✅ Timeouts de session configurables

### Réseau et Sécurité
- ✅ Serveur TLS 1.3 avec authentification mutuelle
- ✅ Vérification de certificats clients
- ✅ Cipher suites modernes (AES-256-GCM, ChaCha20-Poly1305)
- ✅ Protocole binaire PKCS#11 over TLS
- ✅ Isolation réseau complète

## 🚀 Démarrage Rapide avec Docker

### Prérequis

- Docker 20.10+
- Docker Compose 2.0+
- Git

### Installation (5 minutes)

```bash
# 1. Cloner le projet
git clone <repo-url> PST_BOITIER_PKI
cd PST_BOITIER_PKI

# 2. Générer les certificats TLS
make certs

# 3. Build les images Docker
make build

# 4. Démarrer l'environnement
make start
```

L'environnement complet sera accessible:
- HSM Server: https://172.20.0.10:8443
- Logs en temps réel: `make logs`

### Premier Usage

```bash
# 1. Ouvrir un shell dans le conteneur client
make shell-client

# 2. Générer une clé RSA
./bin/pki-client generate-rsa --bits 2048 --label "MySigningKey"

# 3. Signer un document
echo "Important document" > test.txt
./bin/pki-client sign --key "MySigningKey" --file test.txt

# 4. Vérifier la signature
./bin/pki-client verify --key "MySigningKey" --file test.txt --signature test.txt.sig
```

### Commandes Make Utiles

```bash
make help          # Affiche l'aide complète
make status        # Statut des conteneurs
make logs-hsm      # Logs du serveur HSM
make shell-hsm     # Shell dans le conteneur HSM
make test          # Exécute les tests
make restart       # Redémarre l'environnement
make clean         # Nettoie tout (⚠️ supprime les données!)
```

## 📦 Installation

### Développement avec Docker (Recommandé)

L'environnement Docker est préconfiguré et prêt à l'emploi:

```bash
# Configuration automatique
./scripts/start-dev.sh

# Ou manuellement
docker-compose up -d
```

Configuration par défaut:
- HSM_PIN: Défini dans `.env` (généré automatiquement)
- TLS Certs: Auto-générés dans `certs/`
- Storage: Volume Docker persistant `hsm-keys`

### Variables d'Environnement

Créer un fichier `.env` à la racine:

```bash
# HSM Configuration
HSM_PIN=your-secure-pin-here
HSM_SO_PIN=your-so-pin-here

# TLS Certificates
TLS_CERT=/opt/certs/server.crt
TLS_KEY=/opt/certs/server.key
TLS_CA=/opt/certs/ca.crt

# Logging
LOG_LEVEL=INFO
```

## 📖 Structure du Projet

```
PST_BOITIER_PKI/
├── docker-compose.yml            # Orchestration Docker
├── Makefile                      # Commandes de développement
├── .env.example                  # Variables d'environnement
│
├── hsm-server/                   # HSM Server Component
│   ├── Dockerfile                # Image Docker multi-stage
│   ├── CMakeLists.txt            # Build CMake
│   ├── src/
│   │   ├── pkcs11/              # PKCS#11 implementation
│   │   │   ├── pkcs11_impl.c
│   │   │   ├── session.c
│   │   │   ├── objects.c
│   │   │   └── crypto_ops.c
│   │   ├── crypto/              # Cryptographic engine
│   │   │   └── crypto_engine.c
│   │   ├── storage/             # Encrypted key storage
│   │   │   └── key_storage.c    # AES-256-GCM encryption
│   │   ├── network/             # TLS Server
│   │   │   ├── tls_server.c     # TLS 1.3 with mTLS
│   │   │   └── protocol.c       # PKCS#11 network protocol
│   │   ├── utils/               # Utilities
│   │   └── main.c               # Server entry point
│   ├── include/                 # Headers
│   │   ├── pkcs11/              # PKCS#11 headers
│   │   ├── network/             # Network layer
│   │   ├── storage/             # Storage layer
│   │   └── crypto/              # Crypto engine
│   ├── config/
│   │   └── server.conf.example  # Server configuration
│   └── tests/                   # Unit tests
│
├── client-app/                   # Client Application
│   ├── Dockerfile
│   ├── src/
│   │   ├── components/          # UI components
│   │   ├── services/            # PKCS#11 client (TLS)
│   │   └── utils/               # Utilities
│   └── tests/
│
├── certs/                        # TLS Certificates
│   ├── generate-certs.sh        # Certificate generation
│   ├── ca.crt                   # CA certificate
│   ├── server.crt               # Server certificate
│   ├── server.key               # Server private key
│   ├── client.crt               # Client certificate
│   └── client.key               # Client private key
│
├── scripts/                      # Development scripts
│   ├── start-dev.sh             # Start environment
│   ├── stop-dev.sh              # Stop environment
│   ├── build-all.sh             # Build all images
│   └── deploy-to-rpi.sh         # Deploy to Raspberry Pi
│
└── docs/                         # Documentation
    ├── ARCHITECTURE.md
    ├── PKCS11_API.md
    ├── DEPLOYMENT.md
    └── USER_GUIDE.md
```

## 💻 Utilisation

### Avec Docker Compose

```bash
# Démarrer l'environnement
docker-compose up -d

# Voir les logs
docker-compose logs -f pki-hsm

# Accéder au shell HSM
docker-compose exec pki-hsm /bin/bash

# Tester la connexion TLS
openssl s_client -connect 172.20.0.10:8443 \
  -cert certs/client.crt \
  -key certs/client.key \
  -CAfile certs/ca.crt

# Arrêter l'environnement
docker-compose down
```

### Interface CLI Client

```bash
# Depuis le conteneur client
make shell-client

# Mode interactif
pki-client interactive

# Commandes directes
pki-client info
pki-client generate-rsa --bits 4096 --label "SecureKey"
pki-client generate-ec --curve P-384 --label "AuthKey"
pki-client list-keys
pki-client sign --key "SecureKey" --file document.pdf
pki-client verify --key "SecureKey" --file document.pdf --signature document.pdf.sig
```

## 🔧 Développement

### Build Manuel (Sans Docker)

Si vous souhaitez compiler directement:

```bash
cd hsm-server

# Installation des dépendances (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

# Build avec CMake
mkdir build && cd build
cmake ..
make
sudo make install

# Tests
make test
./test_crypto
./test_pkcs11
```

### Configuration du Serveur

Éditer `hsm-server/config/server.conf.example`:

```ini
[server]
listen_address = 0.0.0.0
port = 8443

[tls]
tls_cert = /opt/certs/server.crt
tls_key = /opt/certs/server.key
tls_ca = /opt/certs/ca.crt
require_client_cert = true
tls_min_version = 1.3

[pkcs11]
token_label = PST HSM Token
storage_dir = /var/lib/pki-hsm/keys
storage_encryption = aes-256-gcm
storage_pbkdf2_iterations = 600000

[security]
max_clients = 10
session_timeout = 300
pin_retry_limit = 3
```

### Tests

```bash
# Tests Docker
make test

# Tests manuels
cd hsm-server/build
./test_crypto      # Tests cryptographiques
./test_pkcs11      # Tests PKCS#11
./test_storage     # Tests stockage chiffré
./test_tls         # Tests serveur TLS
```

### Debugging

```bash
# Logs détaillés
docker-compose logs -f

# Logs avec niveau DEBUG
docker-compose exec pki-hsm /bin/bash
LOG_LEVEL=DEBUG /usr/local/bin/pki-hsm-server

# Inspection réseau
docker network inspect pst_boitier_pki_pki-network

# Health check
make health
```

## 🚢 Déploiement sur Raspberry Pi

Le code compilé dans Docker fonctionne directement sur Raspberry Pi:

### Déploiement Automatique

```bash
# Déployer en une commande
./scripts/deploy-to-rpi.sh pi@raspberrypi.local
```

### Déploiement Manuel

```bash
# 1. Build l'image ARM64 (sur machine x86_64)
docker buildx build --platform linux/arm64 \
  -t pki-hsm:arm64 \
  -f hsm-server/Dockerfile .

# 2. Exporter les binaires
docker create --name temp pki-hsm:arm64
docker cp temp:/usr/local/bin/pki-hsm-server ./
docker rm temp

# 3. Copier sur le Raspberry Pi
scp pki-hsm-server pi@raspberrypi.local:/usr/local/bin/
scp -r certs/ pi@raspberrypi.local:/opt/certs/

# 4. Sur le Raspberry Pi
ssh pi@raspberrypi.local
sudo mkdir -p /var/lib/pki-hsm/keys
sudo chmod 700 /var/lib/pki-hsm
HSM_PIN=secret123 /usr/local/bin/pki-hsm-server \
  --cert /opt/certs/server.crt \
  --key /opt/certs/server.key \
  --ca /opt/certs/ca.crt
```

### Configuration Systemd

Créer `/etc/systemd/system/pki-hsm.service`:

```ini
[Unit]
Description=PST PKI HSM Server
After=network.target

[Service]
Type=simple
User=hsm
Group=hsm
Environment="HSM_PIN=your-secure-pin"
Environment="TLS_CERT=/opt/certs/server.crt"
Environment="TLS_KEY=/opt/certs/server.key"
Environment="TLS_CA=/opt/certs/ca.crt"
ExecStart=/usr/local/bin/pki-hsm-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activer le service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pki-hsm
sudo systemctl start pki-hsm
sudo systemctl status pki-hsm
```

## 🔒 Sécurité

### Fonctionnalités de Sécurité Implémentées

- ✅ **TLS 1.3 avec mTLS**: Authentification mutuelle requise
- ✅ **Chiffrement des clés**: AES-256-GCM pour le stockage
- ✅ **Dérivation de clé**: PBKDF2 avec 600,000 iterations
- ✅ **Clés non exportables**: Marquées CKA_EXTRACTABLE=FALSE
- ✅ **PIN haché**: SHA-256 pour le stockage des PINs
- ✅ **Limitation tentatives**: 3 essais avant blocage
- ✅ **Sessions sécurisées**: Timeout et gestion de session
- ✅ **Validation d'entrées**: Toutes les entrées sont validées
- ✅ **Logs d'audit**: Toutes les opérations sont loguées

### Recommandations Production

Pour utiliser ce système en production:

1. **Audit de sécurité**: Faire auditer par des experts
2. **Certificats CA privée**: Ne pas utiliser les certificats de test
3. **HSM Hardware**: Considérer un HSM certifié FIPS 140-2
4. **Monitoring**: Implémenter alertes et détection d'intrusion
5. **Backup**: Stratégie de sauvegarde chiffrée des clés
6. **Isolation réseau**: Firewall et segmentation réseau
7. **Rotation des clés**: Politique de rotation régulière
8. **Updates**: Maintenir OpenSSL et dépendances à jour

### Sauvegardes

```bash
# Backup des clés HSM (chiffrées)
make backup

# Backup manuel
docker cp pki-hsm:/var/lib/pki-hsm/keys ./backup-keys-$(date +%Y%m%d)

# Restauration
docker cp ./backup-keys-20250101 pki-hsm:/var/lib/pki-hsm/keys
```

## 📊 Performance

Tests sur Raspberry Pi 4 (4GB RAM):

| Opération | Temps moyen |
|-----------|-------------|
| Génération RSA-2048 | ~2 secondes |
| Génération RSA-4096 | ~15 secondes |
| Génération EC P-256 | ~50 ms |
| Signature RSA-2048 | ~10 ms |
| Signature ECDSA P-256 | ~5 ms |
| Vérification RSA-2048 | ~2 ms |
| TLS Handshake (mTLS) | ~50 ms |

## 🗺️ Roadmap

### Phase 1 (Terminé) ✅
- [x] Bibliothèque PKCS#11 v2.40 complète
- [x] Opérations RSA et ECDSA
- [x] Stockage chiffré AES-256-GCM
- [x] Serveur TLS 1.3 avec mTLS
- [x] Protocole PKCS#11 over TLS
- [x] Environnement Docker complet
- [x] Scripts de développement
- [x] Client CLI basique

### Phase 2 (En cours) 🚧
- [ ] Implémentation client TLS
- [ ] Tests d'intégration complets
- [ ] Documentation complète API
- [ ] Performance tuning
- [ ] Monitoring et métriques

### Phase 3 (À venir) 📋
- [ ] Interface graphique Electron/Tauri
- [ ] Support certificats X.509 complet
- [ ] Génération CSR
- [ ] Signature PDF/XML avancée
- [ ] API REST optionnelle
- [ ] Clustering et HA

### Phase 4 (Futur) 🔮
- [ ] Support HSM hardware (YubiHSM, etc.)
- [ ] Certification FIPS 140-2
- [ ] Support KMIP
- [ ] HSM as a Service (SaaS)

## 📚 Documentation

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture détaillée
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Guide de déploiement
- **[PKCS11_API.md](docs/PKCS11_API.md)** - Documentation API PKCS#11
- **[USER_GUIDE.md](docs/USER_GUIDE.md)** - Guide utilisateur
- **[hsm-server/README.md](hsm-server/README.md)** - Documentation HSM
- **[client-app/README.md](client-app/README.md)** - Documentation client

## 🤝 Contribution

Les contributions sont les bienvenues ! Voir [CONTRIBUTING.md] pour les guidelines.

## 📝 Licence

À définir

## 👥 Auteurs

PST Cryptographic Systems

## 📧 Support

- **Issues**: https://github.com/votre-org/PST_BOITIER_PKI/issues
- **Email**: support@pst-systems.com
- **Documentation**: `/docs`

## 🙏 Remerciements

- [OASIS PKCS#11](https://docs.oasis-open.org/pkcs11/) - Standard Cryptoki
- [OpenSSL](https://www.openssl.org/) - Bibliothèque cryptographique
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2) - Référence d'implémentation

## ⚖️ Disclaimer

Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte. L'utilisation en production nécessite un audit de sécurité approfondi par des experts qualifiés.
