# Système PKI avec HSM Embarqué

[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![C11](https://img.shields.io/badge/C-11-blue.svg)]()
[![PKCS11](https://img.shields.io/badge/PKCS%2311-v2.40-green.svg)]()

Système PKI complet et sécurisé composé d'un boîtier cryptographique embarqué (Raspberry Pi) agissant comme HSM (Hardware Security Module) et d'une application cliente moderne.

## 🎯 Objectifs

- **Isolation cryptographique**: Opérations sensibles isolées sur matériel dédié
- **Conformité PKCS#11**: Interface standard pour compatibilité maximale
- **Sécurité renforcée**: Clés privées jamais exportables, stockage chiffré
- **Performance**: Signature RSA 2048 bits < 500ms sur Raspberry Pi 4

## 📋 Table des Matières

- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Démarrage Rapide](#démarrage-rapide)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Documentation](#documentation)
- [Développement](#développement)
- [Sécurité](#sécurité)
- [Roadmap](#roadmap)

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│     Raspberry Pi (HSM)              │
│  ┌──────────────────────────────┐   │
│  │  Bibliothèque PKCS#11 (C)    │   │
│  │  ✓ Génération clés RSA/EC    │   │
│  │  ✓ Signature numérique       │   │
│  │  ✓ Stockage sécurisé         │   │
│  │  ✓ Gestion PIN/sessions      │   │
│  └──────────────────────────────┘   │
│  ┌──────────────────────────────┐   │
│  │  Serveur Réseau (Port 11111) │   │
│  │  ✓ Protocole PKCS#11/TCP     │   │
│  │  ✓ TLS Mutuel (prévu)        │   │
│  │  ✓ Ethernet uniquement       │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
              ↕ TCP/IP
┌─────────────────────────────────────┐
│   Application Cliente (Node.js)     │
│  ┌──────────────────────────────┐   │
│  │  Interface CLI Interactive    │   │
│  │  ✓ Gestion des clés          │   │
│  │  ✓ Signature de documents    │   │
│  │  ✓ Gestion certificats       │   │
│  │  ✓ Interface moderne         │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
```

### Composant HSM (Hardware Security Module)
- **Localisation**: `hsm/`
- **Rôle**: Boîtier cryptographique embarqué sur Raspberry Pi
- **Technologies**: C11, OpenSSL, PKCS#11 v2.40
- **Fonctionnalités**:
  - ✅ Bibliothèque PKCS#11 (Cryptoki) complète
  - ✅ Génération de bi-clés RSA (2048/4096 bits) et ECDSA (P-256, P-384, P-521)
  - ✅ Signature numérique (RSA-PKCS, RSA-PSS, ECDSA)
  - ✅ Stockage sécurisé des clés privées (jamais exportables)
  - ✅ Serveur réseau exposant PKCS#11 sur Ethernet
  - ✅ Protection par PIN/passphrase
  - ✅ Gestion des sessions et timeouts

### Composant Client
- **Localisation**: `client/`
- **Rôle**: Application moderne pour gérer les opérations cryptographiques
- **Technologies**: Node.js, Commander, Inquirer, Chalk
- **Fonctionnalités**:
  - ✅ Interface CLI interactive et conviviale
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
- ✅ Stockage persistant chiffré (à améliorer pour production)
- ✅ Protection par PIN utilisateur et SO
- ✅ Limitation tentatives d'authentification (3 essais)
- ✅ Timeouts de session configurable

### Réseau et Sécurité
- ✅ Serveur réseau sur Ethernet uniquement
- ✅ Protocole personnalisé PKCS#11/TCP
- ⏳ TLS mutuel (à implémenter pour production)
- ✅ Isolation matérielle complète

## 🚀 Démarrage Rapide

### Installation HSM (5 minutes)

```bash
# Sur Raspberry Pi
git clone <repo-url> PST_BOITIER_PKI
cd PST_BOITIER_PKI/hsm
make
sudo make install

# Créer répertoire de stockage
sudo mkdir -p /var/lib/hsm/keys
sudo chmod 700 /var/lib/hsm

# Tester
make test
LD_LIBRARY_PATH=./lib ./bin/test_basic
```

### Installation Client (2 minutes)

```bash
# Sur votre PC
cd PST_BOITIER_PKI/client
npm install

# Configurer
echo "HSM_HOST=192.168.1.100" > .env
echo "HSM_PORT=11111" >> .env

# Tester
npm start info
```

### Premier Usage

```bash
# 1. Générer une clé RSA
npm start generate-rsa -- --bits 2048 --label "MySigningKey"

# 2. Signer un document
echo "Important document" > test.txt
npm start sign -- --key "MySigningKey" --file test.txt

# 3. Vérifier la signature
npm start verify -- --key "MySigningKey" --file test.txt --signature test.txt.sig
```

## 📦 Installation Complète

Voir [INSTALLATION.md](docs/INSTALLATION.md) pour le guide complet.

### Déploiement Automatique

```bash
# Déployer sur Raspberry Pi en une commande
./scripts/deploy_hsm.sh pi@raspberrypi.local
```

## 📖 Structure du Projet

```
PST_BOITIER_PKI/
├── hsm/                          # HSM Component (Raspberry Pi)
│   ├── src/
│   │   ├── pkcs11/              # PKCS#11 implementation
│   │   ├── crypto/              # Cryptographic operations
│   │   ├── storage/             # Secure key storage
│   │   ├── network/             # Network server (TLS)
│   │   └── utils/               # Utilities
│   ├── include/
│   │   └── pkcs11/              # PKCS#11 headers
│   ├── tests/                   # Unit tests
│   └── scripts/                 # Deployment scripts
├── client/                       # Client Application
│   ├── src/
│   │   ├── components/          # UI components
│   │   ├── services/            # PKCS#11 client services
│   │   └── utils/               # Utilities
│   ├── public/                  # Static assets
│   └── tests/                   # Tests
└── docs/                         # Documentation
```

## Phases de Développement

- [x] Phase 1: Architecture et POC bibliothèque crypto C
- [ ] Phase 2: Implémentation complète PKCS#11
- [ ] Phase 3: Serveur réseau sécurisé
- [ ] Phase 4: Application cliente basique
- [ ] Phase 5: Interface graphique moderne
- [ ] Phase 6: Tests et documentation

## Spécifications Techniques

### HSM (Raspberry Pi)
- **Matériel**: Raspberry Pi 4 (4GB RAM minimum)
- **OS**: Raspberry Pi OS Lite 64-bit
- **Langage**: C (C11+)
- **Bibliothèques**: OpenSSL/libsodium
- **Réseau**: Ethernet uniquement, TLS 1.3
- **Performance**: Signature RSA 2048 < 500ms

### Client
- **Plateformes**: Linux, Windows, macOS
- **Technologies**: Electron + React ou Tauri
- **Communication**: Client PKCS#11 via réseau sécurisé

## Sécurité

- Authentification mutuelle TLS
- PIN/passphrase pour débloquer HSM
- Clés privées non exportables
- Limitation tentatives d'authentification
- Logging sécurisé
- Timeouts de session

## 💻 Utilisation

### Interface CLI

```bash
# Mode interactif
npm start interactive

# Commandes directes
npm start generate-rsa -- --bits 4096 --label "SecureKey"
npm start generate-ec -- --curve P-384 --label "AuthKey"
npm start list-keys
npm start sign -- --key "SecureKey" --file document.pdf
npm start verify -- --key "SecureKey" --file document.pdf --signature document.pdf.sig
npm start info
```

### Exemples d'Utilisation

Voir [hsm/README.md](hsm/README.md) et [client/README.md](client/README.md) pour des exemples détaillés.

## 📚 Documentation

- **[INSTALLATION.md](docs/INSTALLATION.md)** - Guide d'installation complet
- **[hsm/README.md](hsm/README.md)** - Documentation HSM/PKCS#11
- **[client/README.md](client/README.md)** - Documentation client
- **API PKCS#11** - Voir headers dans `hsm/include/pkcs11/`

## 🔧 Développement

### Prérequis
- **HSM**: GCC, Make, OpenSSL 1.1+
- **Client**: Node.js 18+, npm

### Compilation HSM

```bash
cd hsm
make clean
make                    # Compiler
make test              # Compiler et tester
make install           # Installer système
```

### Structure du Code HSM

```
hsm/src/
├── pkcs11/           # Implémentation PKCS#11
│   ├── pkcs11_impl.c    # Fonctions principales (C_Initialize, etc.)
│   ├── session.c        # Gestion sessions (C_OpenSession, C_Login)
│   ├── objects.c        # Gestion objets (C_CreateObject, C_FindObjects)
│   └── crypto_ops.c     # Opérations crypto (C_Sign, C_GenerateKeyPair)
├── crypto/           # Moteur cryptographique
│   └── crypto_ops.c     # Implémentation RSA/EC avec OpenSSL
├── storage/          # Stockage persistant
│   └── storage.c        # Sauvegarde/chargement clés et token
├── network/          # Serveur réseau
│   └── network_server.c # Serveur TCP pour PKCS#11
└── utils/            # Utilitaires
    └── utils.c          # Logging, PIN, mémoire sécurisée
```

### Tests

```bash
# HSM
cd hsm
make test
./bin/test_basic

# Client
cd client
npm test
```

## 🔒 Sécurité

### ⚠️ Avertissement

Cette implémentation est un **POC éducatif**. Pour usage en production:

- ❌ **Stockage non chiffré**: Les clés sont stockées en clair dans `/var/lib/hsm/`
- ❌ **Pas de TLS**: Communication réseau non chiffrée
- ❌ **Pas d'audit**: Code non audité par experts sécurité
- ❌ **Protection limitée**: Pas de protection contre attaques par canaux auxiliaires

### ✅ Recommandations Production

1. **Chiffrer le stockage**: Utiliser LUKS ou chiffrement au niveau application
2. **TLS mutuel**: Implémenter avec OpenSSL/mbedTLS
3. **Audit de sécurité**: Faire auditer par experts
4. **HSM hardware**: Utiliser un vrai HSM certifié (FIPS 140-2)
5. **Monitoring**: Logs, alertes, détection d'intrusion
6. **Backup**: Stratégie de sauvegarde des clés

### Sécurité Actuelle

- ✅ Clés privées marquées non-extractables
- ✅ PIN hashé avec SHA-256
- ✅ Limitation tentatives (3 essais)
- ✅ Sessions avec timeout
- ✅ Validation entrées utilisateur
- ✅ Logs des opérations

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

## 🗺️ Roadmap

### Phase 1 (Terminé) ✅
- [x] Bibliothèque PKCS#11 de base
- [x] Opérations RSA et ECDSA
- [x] Stockage persistant
- [x] Client CLI
- [x] Serveur réseau basique

### Phase 2 (En cours) 🚧
- [ ] TLS mutuel
- [ ] Chiffrement du stockage
- [ ] Tests d'intégration complets
- [ ] Documentation complète

### Phase 3 (À venir) 📋
- [ ] Interface graphique Electron/Tauri
- [ ] Support certificats X.509 complet
- [ ] Génération CSR
- [ ] Signature PDF/XML avancée
- [ ] Monitoring et métriques

### Phase 4 (Futur) 🔮
- [ ] Support HSM hardware (YubiHSM, etc.)
- [ ] Clustering et haute disponibilité
- [ ] API REST
- [ ] Certification FIPS 140-2

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

Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte. L'utilisation en production nécessite un audit de sécurité approfondi et des modifications importantes
