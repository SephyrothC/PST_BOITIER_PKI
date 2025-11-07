# PST HSM Client Application

Application cliente moderne pour interagir avec le HSM PST via PKCS#11.

## Fonctionnalités

### Interface CLI
- Gestion des clés (génération, liste, suppression)
- Signature de documents
- Vérification de signatures
- Gestion des certificats
- Export/Import de clés publiques

### Interface Graphique (Future)
- Dashboard avec statut HSM
- Visualisation des clés et certificats
- Drag & drop pour signature de documents
- Logs d'opérations en temps réel

## Installation

### Prérequis

```bash
# Node.js 18+ requis
node --version

# Installer les dépendances
npm install
```

## Utilisation

### Mode CLI

```bash
# Démarrer le client CLI
npm start

# Commandes disponibles
npm start -- --help

# Générer une paire de clés RSA
npm start generate-rsa --bits 2048 --label "MyKey"

# Générer une paire de clés EC
npm start generate-ec --curve P-256 --label "MyECKey"

# Lister les clés
npm start list-keys

# Signer un document
npm start sign --key "MyKey" --file document.pdf --output document.sig

# Vérifier une signature
npm start verify --key "MyKey" --file document.pdf --signature document.sig
```

### Configuration

Créer un fichier `.env` :

```bash
HSM_HOST=192.168.1.100
HSM_PORT=11111
HSM_PIN=user1234
HSM_SLOT=0
```

## Développement

### Structure du Projet

```
client/
├── src/
│   ├── cli.js              # Interface CLI
│   ├── services/
│   │   ├── pkcs11.js       # Client PKCS#11
│   │   ├── network.js      # Communication réseau
│   │   └── crypto.js       # Opérations crypto
│   ├── components/         # Composants UI (future)
│   └── utils/              # Utilitaires
├── tests/                  # Tests
├── package.json
└── README.md
```

### Lancer en mode développement

```bash
npm run dev
```

### Tests

```bash
npm test
```

## Exemples

### Génération de clé RSA

```bash
$ npm start generate-rsa -- --bits 2048 --label "SigningKey"

✓ Connecting to HSM...
✓ Authenticating...
✓ Generating RSA-2048 key pair...

Public Key:  0x10000001
Private Key: 0x20000001

Key pair generated successfully!
```

### Signature de document

```bash
$ npm start sign -- --key "SigningKey" --file contract.pdf

✓ Loading document...
✓ Finding private key...
✓ Signing document...

Signature saved to: contract.pdf.sig
Signature length: 256 bytes
```

## Roadmap

- [x] Client CLI de base
- [ ] Client réseau PKCS#11
- [ ] Interface graphique Electron
- [ ] Support des certificats X.509
- [ ] Génération de CSR
- [ ] Signature PDF avancée
- [ ] Signature XML (XAdES)

## Licence

À définir

## Support

Voir la documentation complète dans `/docs`.
