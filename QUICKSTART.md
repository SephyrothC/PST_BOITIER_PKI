# Démarrage Rapide - PST HSM PKI

Guide ultra-rapide pour démarrer en moins de 10 minutes.

## 🎯 Objectif

Installer et tester le système PKI complet:
- HSM sur Raspberry Pi
- Client sur votre PC
- Génération de clés et signature

## ⏱️ Temps Estimé

- Installation HSM: 5 minutes
- Installation Client: 2 minutes
- Tests: 3 minutes
- **Total: 10 minutes**

## 📋 Prérequis

### Pour le HSM (Raspberry Pi)
- Raspberry Pi 4 avec Raspberry Pi OS Lite 64-bit
- Connexion Ethernet
- SSH activé

### Pour le Client (PC/Mac/Linux)
- Node.js 18+
- Connexion réseau au Raspberry Pi

## 🚀 Installation

### Étape 1: HSM (Raspberry Pi)

```bash
# Se connecter au Raspberry Pi
ssh pi@raspberrypi.local

# Installer dépendances (30 sec)
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev git

# Cloner et compiler (2 min)
git clone <votre-repo> PST_BOITIER_PKI
cd PST_BOITIER_PKI/hsm
make

# Installer (10 sec)
sudo make install
sudo mkdir -p /var/lib/hsm/keys
sudo chmod 700 /var/lib/hsm

# Tester (1 min)
make test
LD_LIBRARY_PATH=./lib ./bin/test_basic
```

**✅ Si vous voyez "All tests completed successfully!", c'est bon !**

### Étape 2: Client (PC)

```bash
# Sur votre PC
cd PST_BOITIER_PKI/client

# Installer dépendances (1 min)
npm install

# Configurer (5 sec)
cat > .env << EOF
HSM_HOST=192.168.1.100
HSM_PORT=11111
HSM_PIN=user1234
EOF

# Tester (5 sec)
npm start info
```

**✅ Si vous voyez les informations du HSM, c'est bon !**

## 🎮 Premier Test

### 1. Générer une clé RSA

```bash
npm start generate-rsa -- --bits 2048 --label "TestKey"
```

Sortie attendue:
```
🔐 PST HSM - Generate RSA Key Pair
✓ Connected to HSM
✓ Key pair generated successfully!

✓ Success!

Public Key:  0x10000001
Private Key: 0x20000001
Label:       TestKey
Size:        2048 bits
```

### 2. Signer un document

```bash
# Créer un fichier test
echo "Document important à signer" > test.txt

# Signer
npm start sign -- --key "TestKey" --file test.txt
```

Sortie attendue:
```
✍️  PST HSM - Sign Document
✓ Document loaded: test.txt
✓ Private key found
✓ Document signed successfully!

✓ Success!

Signature:  test.txt.sig
Algorithm:  SHA256-RSA
Length:     256 bytes
```

### 3. Vérifier la signature

```bash
npm start verify -- --key "TestKey" --file test.txt --signature test.txt.sig
```

Sortie attendue:
```
🔍 PST HSM - Verify Signature
✓ Files loaded
✓ Public key found
✓ Signature is VALID!

✓ Signature verified successfully!
```

## 🎉 Succès !

Vous avez un système PKI fonctionnel !

## 📚 Prochaines Étapes

### Explorer les fonctionnalités

```bash
# Mode interactif
npm start interactive

# Générer clé EC
npm start generate-ec -- --curve P-256 --label "ECKey"

# Lister toutes les clés
npm start list-keys

# Voir infos HSM
npm start info
```

### Utiliser en production

⚠️ **ATTENTION**: Ce système est un POC éducatif !

Pour la production:
1. Lire [docs/INSTALLATION.md](docs/INSTALLATION.md)
2. Activer le chiffrement du stockage
3. Configurer TLS mutuel
4. Faire un audit de sécurité
5. Utiliser un vrai HSM hardware

### Documentation Complète

- [README.md](README.md) - Vue d'ensemble
- [docs/INSTALLATION.md](docs/INSTALLATION.md) - Installation détaillée
- [hsm/README.md](hsm/README.md) - Documentation HSM
- [client/README.md](client/README.md) - Documentation client

## 🐛 Dépannage Rapide

### Le test HSM échoue

```bash
# Vérifier que le répertoire existe
ls -la /var/lib/hsm
# Doit afficher: drwx------ pi pi

# Si non, créer:
sudo mkdir -p /var/lib/hsm/keys
sudo chown -R pi:pi /var/lib/hsm
sudo chmod 700 /var/lib/hsm
```

### Le client ne se connecte pas

```bash
# Vérifier la connectivité
ping 192.168.1.100

# Vérifier le port
nc -zv 192.168.1.100 11111

# Démarrer le serveur HSM manuellement
ssh pi@raspberrypi.local
cd ~/PST_BOITIER_PKI/hsm
# TODO: compiler et lancer le serveur réseau
```

### npm install échoue

```bash
# Vérifier Node.js
node --version
# Doit être >= 18

# Mettre à jour npm
npm install -g npm@latest

# Réessayer
rm -rf node_modules package-lock.json
npm install
```

## 💡 Astuces

### Alias Pratiques

Ajoutez à votre `~/.bashrc`:

```bash
alias hsm-gen-rsa='npm --prefix ~/PST_BOITIER_PKI/client start generate-rsa --'
alias hsm-gen-ec='npm --prefix ~/PST_BOITIER_PKI/client start generate-ec --'
alias hsm-sign='npm --prefix ~/PST_BOITIER_PKI/client start sign --'
alias hsm-verify='npm --prefix ~/PST_BOITIER_PKI/client start verify --'
alias hsm-list='npm --prefix ~/PST_BOITIER_PKI/client start list-keys'
```

Puis:
```bash
hsm-gen-rsa --bits 2048 --label "MyKey"
hsm-sign --key "MyKey" --file document.pdf
```

### Script de Test Complet

```bash
#!/bin/bash
# test-pki.sh - Test complet du système

echo "Test du système PKI..."

# 1. Générer clés
npm start generate-rsa -- --bits 2048 --label "TestRSA"
npm start generate-ec -- --curve P-256 --label "TestEC"

# 2. Créer fichier test
echo "Document de test $(date)" > test-$(date +%s).txt
FILE=$(ls -t test-*.txt | head -1)

# 3. Signer avec RSA
npm start sign -- --key "TestRSA" --file "$FILE"

# 4. Vérifier
npm start verify -- --key "TestRSA" --file "$FILE" --signature "$FILE.sig"

echo "✓ Test terminé avec succès!"
```

## 📞 Besoin d'Aide ?

- **Documentation**: [README.md](README.md)
- **Issues**: https://github.com/votre-org/PST_BOITIER_PKI/issues
- **Email**: support@pst-systems.com

Bon cryptage ! 🔐
