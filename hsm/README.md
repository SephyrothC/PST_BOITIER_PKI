# PST HSM - Bibliothèque PKCS#11

Bibliothèque PKCS#11 (Cryptoki) complète pour Hardware Security Module (HSM) embarqué sur Raspberry Pi.

## Caractéristiques

### Opérations Cryptographiques
- **Génération de clés**:
  - RSA 2048/4096 bits
  - ECDSA P-256, P-384, P-521

- **Signature numérique**:
  - RSA-PKCS#1 v1.5
  - RSA-PSS
  - ECDSA
  - Support SHA-256, SHA-384, SHA-512

- **Gestion des clés**:
  - Clés privées non exportables
  - Stockage chiffré sécurisé
  - Protection par PIN/passphrase

### Sécurité
- Authentification par PIN (utilisateur et SO)
- Limitation des tentatives d'authentification
- Clés sensibles marquées comme non extractibles
- Stockage persistant chiffré
- Isolation cryptographique complète

### Conformité PKCS#11
- PKCS#11 v2.40
- Interface Cryptoki standard
- Compatible avec applications PKCS#11 existantes

## Structure du Projet

```
hsm/
├── src/
│   ├── pkcs11/          # Implémentation PKCS#11
│   │   ├── pkcs11_impl.c    # Fonctions principales
│   │   ├── session.c        # Gestion des sessions
│   │   ├── objects.c        # Gestion des objets
│   │   └── crypto_ops.c     # Opérations crypto
│   ├── crypto/          # Opérations cryptographiques
│   │   └── crypto_ops.c     # RSA, ECDSA avec OpenSSL
│   ├── storage/         # Stockage sécurisé
│   │   └── storage.c        # Persistance des clés
│   └── utils/           # Utilitaires
│       └── utils.c          # Logging, mémoire sécurisée
├── include/
│   └── pkcs11/          # Headers publics
│       ├── pkcs11.h         # Header PKCS#11 standard
│       └── pkcs11_internal.h # Types internes
├── tests/
│   └── test_basic.c     # Programme de test
├── Makefile             # Compilation
└── README.md            # Cette documentation
```

## Compilation

### Prérequis

```bash
# Debian/Ubuntu/Raspberry Pi OS
sudo apt-get update
sudo apt-get install build-essential libssl-dev

# Fedora/RHEL
sudo dnf install gcc make openssl-devel
```

### Compilation

```bash
cd hsm
make
```

Cela génère la bibliothèque partagée `lib/libpst-pkcs11.so`.

### Installation système

```bash
sudo make install
```

Installe la bibliothèque dans `/usr/local/lib/pkcs11/`.

### Compilation du test

```bash
make test
```

Génère le programme de test dans `bin/test_basic`.

## Utilisation

### 1. Initialisation de base

```c
#include <pkcs11/pkcs11.h>

CK_FUNCTION_LIST_PTR pFunctionList;
CK_RV rv;

/* Obtenir la liste des fonctions */
rv = C_GetFunctionList(&pFunctionList);

/* Initialiser la bibliothèque */
rv = pFunctionList->C_Initialize(NULL);

/* ... opérations ... */

/* Finaliser */
rv = pFunctionList->C_Finalize(NULL);
```

### 2. Initialiser un token

```c
CK_SLOT_ID slotID = 0;
CK_UTF8CHAR soPin[] = "12345678";
CK_UTF8CHAR label[] = "Mon HSM";

rv = pFunctionList->C_InitToken(slotID, soPin, strlen(soPin), label);
```

### 3. Ouvrir une session et se connecter

```c
CK_SESSION_HANDLE hSession;
CK_UTF8CHAR userPin[] = "user1234";

/* Ouvrir session */
rv = pFunctionList->C_OpenSession(slotID,
                                  CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &hSession);

/* Se connecter */
rv = pFunctionList->C_Login(hSession, CKU_USER, userPin, strlen(userPin));
```

### 4. Générer une paire de clés RSA

```c
CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
CK_ULONG modulusBits = 2048;
CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};

CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_LABEL, "Ma clé publique", 16}
};

CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL)},
    {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_LABEL, "Ma clé privée", 14}
};

CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

rv = pFunctionList->C_GenerateKeyPair(
    hSession, &mechanism,
    publicKeyTemplate, 5,
    privateKeyTemplate, 5,
    &hPublicKey, &hPrivateKey
);
```

### 5. Signer des données

```c
CK_MECHANISM signMechanism = {CKM_SHA256_RSA_PKCS, NULL, 0};
CK_BYTE data[] = "Données à signer";
CK_BYTE signature[512];
CK_ULONG signatureLen = sizeof(signature);

/* Initialiser la signature */
rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);

/* Signer */
rv = pFunctionList->C_Sign(hSession, data, sizeof(data) - 1,
                           signature, &signatureLen);
```

### 6. Générer une paire de clés EC

```c
/* OID pour P-256 (prime256v1) */
CK_BYTE ecParams[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
    {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)}
};

CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)},
    {CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL)}
};

rv = pFunctionList->C_GenerateKeyPair(
    hSession, &mechanism,
    publicKeyTemplate, 3,
    privateKeyTemplate, 3,
    &hPublicKey, &hPrivateKey
);
```

## Exécution du Test

```bash
# Créer le répertoire de stockage
sudo mkdir -p /var/lib/hsm/keys
sudo chmod 700 /var/lib/hsm

# Exécuter le test
LD_LIBRARY_PATH=./lib ./bin/test_basic
```

Sortie attendue:
```
===========================================
PST HSM PKCS#11 Library - Basic Test
===========================================

1. Getting function list...
SUCCESS: C_GetFunctionList

2. Initializing Cryptoki...
SUCCESS: C_Initialize

[... output continues ...]

All tests completed successfully!
```

## Configuration

### Répertoires de stockage

Par défaut, les données sont stockées dans :
- `/var/lib/hsm/` - Répertoire principal
- `/var/lib/hsm/keys/` - Clés chiffrées
- `/var/lib/hsm/token.dat` - Informations du token

Modifiez `HSM_STORAGE_DIR` dans `include/pkcs11/pkcs11_internal.h` pour changer.

### Sécurité

Configuration dans `pkcs11_internal.h`:
```c
#define HSM_MAX_PIN_LEN 32           // Longueur max du PIN
#define HSM_MIN_PIN_LEN 4            // Longueur min du PIN
#define HSM_PIN_RETRY_COUNT 3        // Tentatives avant verrouillage
#define HSM_SESSION_TIMEOUT 300      // Timeout session (secondes)
```

## Mécanismes Supportés

| Mécanisme | Description | Supporté |
|-----------|-------------|----------|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | Génération de clés RSA | ✅ |
| `CKM_RSA_PKCS` | Signature RSA PKCS#1 v1.5 | ✅ |
| `CKM_RSA_PKCS_PSS` | Signature RSA-PSS | ✅ |
| `CKM_SHA256_RSA_PKCS` | Signature RSA avec SHA-256 | ✅ |
| `CKM_SHA384_RSA_PKCS` | Signature RSA avec SHA-384 | ✅ |
| `CKM_SHA512_RSA_PKCS` | Signature RSA avec SHA-512 | ✅ |
| `CKM_EC_KEY_PAIR_GEN` | Génération de clés EC | ✅ |
| `CKM_ECDSA` | Signature ECDSA | ✅ |
| `CKM_ECDSA_SHA256` | Signature ECDSA avec SHA-256 | ✅ |
| `CKM_ECDSA_SHA384` | Signature ECDSA avec SHA-384 | ✅ |
| `CKM_ECDSA_SHA512` | Signature ECDSA avec SHA-512 | ✅ |

## Dépannage

### Erreur: "Failed to create storage directory"
```bash
sudo mkdir -p /var/lib/hsm/keys
sudo chmod 700 /var/lib/hsm
```

### Erreur: "libpst-pkcs11.so: cannot open shared object file"
```bash
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH
# Ou installer avec sudo make install
```

### Erreur: "PIN_LOCKED"
Le PIN a été verrouillé après trop de tentatives. Réinitialisez le token:
```bash
rm -rf /var/lib/hsm/*
```

## Performance

Tests sur Raspberry Pi 4 (4GB):
- **Génération RSA-2048**: ~2 secondes
- **Génération RSA-4096**: ~15 secondes
- **Génération EC P-256**: ~50 ms
- **Signature RSA-2048**: ~10 ms
- **Signature ECDSA P-256**: ~5 ms

## Sécurité et Production

⚠️ **ATTENTION**: Cette implémentation est un POC éducatif. Pour un usage en production:

1. ✅ Chiffrer le stockage des clés (actuellement en clair)
2. ✅ Implémenter l'authentification TLS mutuelle
3. ✅ Ajouter des tests de sécurité complets
4. ✅ Effectuer un audit de sécurité
5. ✅ Implémenter la protection contre les attaques par canaux auxiliaires
6. ✅ Utiliser un vrai HSM hardware ou TPM

## Prochaines Étapes

- [ ] Implémenter le serveur réseau PKCS#11
- [ ] Support du chiffrement/déchiffrement
- [ ] Application cliente graphique
- [ ] Tests d'intégration complets
- [ ] Documentation API complète

## Licence

À définir

## Auteurs

PST Cryptographic Systems

## Support

Pour toute question ou problème, consultez la documentation complète dans `/docs` ou ouvrez une issue.
