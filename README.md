# Gestionnaire-de-mots-de-passe-en-ligne-de-commande

Outil en ligne de commande pour la gestion sécurisée de mots de passe, avec chiffrement local et accès rapide aux identifiants via le terminal.
⚠️ Ce projet est pédagogique et ne remplace pas un gestionnaire de mots de passe professionnel.

## Membres
- Roland Ung
- Jeff Bernabeo


## Fonctionnalités indispensables 
### 1 - Initialisation du magasin de mot de passe
- Création du répertoire local ~/.password-store via init.
- Utilisation d’une clé GPG existante pour le chiffrement.
- `pathlib`: crée le répertoire
- `os`: configure les permissions du dossier
- `gnupg` : génère, stocke et utilise une clé GPG

### 2 - Chiffrement et déchiffrement des mots de passe du fichier
- Chiffrement et déchiffrement des mots de passe avec `gnupg`
- Chaque mot de passe est stocké dans un fichier .gpg chiffré.
- Le déchiffrement est déclenché lors de la lecture avec show et edit. 

### 3 - Authentification de l'utilisateur via GPG 
- L’accès aux mots de passe est protégé par la passphrase de la clé GPG.
- Cette passphrase joue le rôle de mot de passe maître.
- `getpass`: entre le passphrase de manière sécurisé

### 4 - Mémorisation du nom d'utilisateur et du mot de passe donné selon l'url.
- **dépend de 1**.
- `json`: convertit le dictionnaire python en json

### 5 - Ajout d'un mot de passe
- **dépend de 1 et 4**.
- `getpass`: entre le mot de passe
- `os`: configure les permissions du fichier

### 6 - Affichage d'un mot de passe
- **dépend de 1 et 4**.
-   Affiche les mots de passe, avec l'identifiant mémorisé et l'URL associée
- `json`: convertit le json en dictionnaire python

### 7 - Edition d'un mot de passe
- **dépend de 1, 4 et 5**.
-   Modifie un mot de passe dans le gestionnaire
- `json`: convertit le json en dictionnaire python
- `getpass`: entre le nouveau mot de passe
- `os`: reconfigure les permissions du fichier

### 8 - Suppresion d'un mot de passe
- **dépend de 1 et 5**.
- `pathlib`: supprime le fichier

### 9 - Liste et recherche d'un mot de passe
- **dépend de 1 et 4**.
- Liste et recherche d'un mot de passe par le nom de fichier
- `glob`: filtrer les fichiers par l'extension .gpg

## Fonctionnalités supplémentaires 
### 10 - Copie du mot de passe dans le presse-papier.
- **dépend de 1 et 4**.
- `pyperclip` : copie le mot de passe et colle dans le presse-papier

### 11 - Génération automatique d'un mot de passe sécurisé.
- Permet au gestionnaire de mot de passe de générer un mot de passe robuste.
- `secrets` : génère une chaine de caractères cryptographiquement sûre
- `string` : fournit l'ensemble des caractères (lettres, chiffres, symboles...)

### 12 - Création d'une date d'ajout
- **dépend de 4 et 5**.
- Permet de connaitre la date de création ou de modification d'un mot de passe
- `datetime` : génère la date actuelle

## Installation et utilisation

### Prérequis
- Python 3.x
- GPG installé sur votre système

### Installation
1. Clonez le dépôt :
```bash
git clone <url-du-depot>
cd Gestionnaire-de-mots-de-passe
```

2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

3. Créez une clé GPG si vous n'en avez pas :
```bash
gpg --full-generate-key
```

### Utilisation

**Initialiser le gestionnaire :**
```bash
python main.py init votre.email@exemple.com
```

**Ajouter un mot de passe :**
```bash
python main.py add gmail -u username --url https://gmail.com
python main.py add facebook -g -l 25  # Génération automatique
```

**Afficher un mot de passe :**
```bash
python main.py show gmail
python main.py show gmail -c  # Copier dans le presse-papiers
```

**Modifier un mot de passe :**
```bash
python main.py edit gmail -u username --url https://gmail.com
```

**Lister les mots de passe :**
```bash
python main.py list
python main.py list -s gmail  # Rechercher
```

**Supprimer un mot de passe :**
```bash
python main.py delete gmail
```

## Structure du projet

```
Gestionnaire-de-mots-de-passe/
│
├── .venv                Environnement virtuel contenant les modules installés
├── password_store/      Magasin de mot de passe crée après 'init'
│   ├── .gpg-id          Email de la clé GPG utilisée pour chiffrer et déchiffrer
│   └── *.gpg            Fichiers chiffrés où sont stockés chaque mot de passe
├── .gitignore           Fichiers à exclure de Git (venv, password_store...)
├── requirements.txt     Liste des dépendances Python
└── main.py              Programme contenant chaque fonction et le 'main'
```
