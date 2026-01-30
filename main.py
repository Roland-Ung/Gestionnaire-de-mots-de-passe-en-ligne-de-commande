import os
from pathlib import Path
import gnupg              
import argparse
import secrets
import string
import getpass
import json
from datetime import datetime
import pyperclip

path_parent = Path(__file__).resolve().parent
store = path_parent / "password_store"

#1 - Initialisation du magasin de mots de passe avec GPG
def init_password_store(gpg_key_email, force=False):
    if not store.exists():
        store.mkdir(mode=0o700, parents=True)
        print(f"Répertoire créé : {store}")
    elif not force:
        print(f"Magasin déjà initialisé dans : {store}")
        return

    gpg = gnupg.GPG()
    keys = gpg.list_keys(secret=True)
    existing_key = None
    
    # Recherche de la clé correspondante
    for key in keys:
        for uid in key.get('uids', []):
            if gpg_key_email in uid:
                existing_key = key
                break
        if existing_key:
            break
    
    if not existing_key:
        print(f"""
        Aucune clé GPG trouvée pour : {gpg_key_email}
        Veuillez créer une clé GPG manuellement :
        gpg --full-generate-key
    """)
        return
    
    else:
        print(f"Clé existante trouvée pour : {gpg_key_email}")
    
    # Sauvegarde de la configuration
    config_file = store / ".gpg-id"
    with open(config_file, 'w') as f:
        f.write(gpg_key_email + '\n')
    
    os.chmod(config_file, 0o600)
    print("Magasin de mots de passe initialisé avec succès !")

#Récupère l'email GPG depuis le fichier .gpg-id.
def get_gpg_email():
    config_file = store / ".gpg-id"
    
    if not config_file.exists():
        print("Erreur : Le magasin n'est pas initialisé.")
        return None
    
    with open(config_file, 'r') as f:
        return f.read().strip()

#4 - Mémorisation du nom d'utilisateur et du mot de passe donné selon l'url.
#5 - Ajout d'un mot de passe
def add_password(name, length=20, generate=False, username=None, url=None):
    
    # Vérifier que le magasin est initialisé
    gpg_email = get_gpg_email()
    if not gpg_email:
        return
    
    # Créer le chemin du fichier
    password_file = store / f"{name}.gpg"
    
    if password_file.exists():
        print(f"Un mot de passe existe déjà pour : {name}")
        return
    
    # Déterminer le mot de passe à utiliser
    if generate:
        password = generate_password(length)
        print(f"Mot de passe généré pour : {name}")
    else:
        # Demander le mot de passe de manière sécurisée
        password = getpass.getpass("Entrez le mot de passe : ")
        password_confirm = getpass.getpass("Confirmez le mot de passe : ")
        
        if password != password_confirm:
            print("Les mots de passe ne correspondent pas")
            return
    
    #12 - Création d'une date d'ajout
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Créer la structure de données
    data = {
        "password": password,
        "username": username,
        "url": url,
        "created_at": current_time,
        "modified_at": current_time
    }
    
    # Convertir en JSON
    json_data = json.dumps(data, indent=2)
    
    # Chiffrer les données
    gpg = gnupg.GPG()
    encrypted = gpg.encrypt(json_data, [gpg_email])
    
    if not encrypted.ok:
        print(f"Erreur de chiffrement : {encrypted.stderr}")
        return
    
    # Sauvegarder le fichier chiffré
    with open(password_file, 'w') as f:
        f.write(str(encrypted))
    
    os.chmod(password_file, 0o600)
    
    print(f"  Mot de passe ajouté : {name}")
    if username:
        print(f"  Identifiant : {username}")
    if url:
        print(f"  URL : {url}")
    if generate:
        print(f"  Mot de passe : {password}")

#6 - Affichage d'un mot de passe
def show_password(name, copy=False):
    password_file = store / f"{name}.gpg"
    
    if not password_file.exists():
        print(f"Aucun mot de passe trouvé pour : {name}")
        return
    
    # Récupérer l'email GPG
    gpg_email = get_gpg_email()
    if not gpg_email:
        return
    
    #3 - Authentification de l'utilisateur via GPG
    passphrase_mdp = getpass.getpass("Entrez la passphrase de votre clé GPG : ")
    
    # Lire le contenu chiffré
    with open(password_file, 'r') as f:
        encrypted_data = f.read()
    
    # Déchiffrer le mot de passe
    gpg = gnupg.GPG()
    decrypted = gpg.decrypt(encrypted_data, passphrase=passphrase_mdp)
    
    if not decrypted.ok:
        print(f"Erreur de déchiffrement")
        return
    
    # Charger les données
    data = json.loads(decrypted.data.decode())
    password = data.get('password', 'N/A')
    
    #10 - Copie du mot de passe dans le presse-papier.
    if copy:
        try:
            pyperclip.copy(password)
            print("Mot de passe copié dans le presse-papiers !")
        except Exception as e:
            print(f"Erreur lors de la copie : {e}")
    
    print(f"\n{'='*50}")
    print(f"Informations pour : {name}")
    print(f"{'='*50}")
    print(f"Mot de passe : {password}")
    if data.get('username'):
        print(f"Identifiant  : {data['username']}")
    if data.get('url'):
        print(f"URL          : {data['url']}")
    if data.get('created_at'):
        print(f"Créé le      : {data['created_at']}")
    if data.get('modified_at'):
        print(f"Modifié le   : {data['modified_at']}")
    print(f"{'='*50}\n")

#7 - Edition d'un mot de passe
def edit_password(name, username=None, url=None):
    password_file = store / f"{name}.gpg"
    
    if not password_file.exists():
        print(f"Aucun mot de passe trouvé pour : {name}")
        return
    
    # Récupérer l'email GPG
    gpg_email = get_gpg_email()
    if not gpg_email:
        return
    
    #3 - Authentification de l'utilisateur via GPG
    passphrase_mdp = getpass.getpass("Entrez la passphrase de votre clé GPG : ")
    with open(password_file, 'r') as f:
        encrypted_data = f.read()
    
    gpg = gnupg.GPG()
    decrypted = gpg.decrypt(encrypted_data, passphrase=passphrase_mdp)
    
    if not decrypted.ok:
        print(f"Erreur de déchiffrement")
        return
    
    # Charger les données existantes
    data = json.loads(decrypted.data.decode())
    
    modified = False
    
    # Modifier l'identifiant si fourni
    if username is not None:
        data["username"] = username
        modified = True
        print(f"Identifiant mis à jour : {username}")
    
    # Modifier l'URL si fournie
    if url is not None:
        data["url"] = url
        modified = True
        print(f"URL mise à jour : {url}")
    
    # Si aucun argument n'est fourni, demander le nouveau mot de passe
    if not modified:
        new_password = getpass.getpass("Entrez le nouveau mot de passe : ")
        new_password_confirm = getpass.getpass("Confirmez le nouveau mot de passe : ")
        
        if new_password != new_password_confirm:
            print("Les mots de passe ne correspondent pas")
            return
        
        data["password"] = new_password
        modified = True

    data["modified_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Convertir en JSON et chiffrer
    json_data = json.dumps(data, indent=2)
    encrypted = gpg.encrypt(json_data, [gpg_email])
    
    if not encrypted.ok:
        print(f"Erreur de chiffrement : {encrypted.stderr}")
        return
    
    # Sauvegarder le fichier chiffré
    with open(password_file, 'w') as f:
        f.write(str(encrypted))
    
    os.chmod(password_file, 0o600)
    
    print(f"✓ Mot de passe modifié : {name}")

#8 - Suppression d'un mot de passe
def delete_password(name):
    password_file = store / f"{name}.gpg"
    
    if not password_file.exists():
        print(f"Aucun mot de passe trouvé pour : {name}")
        return
    
    password_file.unlink()
    print(f"Mot de passe supprimé : {name}")


#9 - Liste et recherche d'un mot de passe
def list_passwords(search=None):
    
    # Vérifier que le magasin est initialisé
    gpg_email = get_gpg_email()
    if not gpg_email:
        return
    
    # Lister tous les fichiers .gpg
    password_files = list(store.glob("*.gpg"))
    
    if not password_files:
        print("Aucun mot de passe enregistré")
        return
    
    # Filtrer par recherche si fournie
    if search:
        password_files = [f for f in password_files if search.lower() in f.stem.lower()]
        
        if not password_files:
            print(f"Aucun mot de passe trouvé pour la recherche : {search}")
            return
    
    # Afficher la liste
    print(f"\n{'='*50}")
    if search:
        print(f"Résultats de recherche pour : {search}")
    else:
        print(f"Liste des mots de passe ({len(password_files)})")
    print(f"{'='*50}")
    
    for pf in sorted(password_files):
        print(f"  • {pf.stem}")
    
    print(f"{'='*50}\n")

#11 - Génération automatique d'un mot de passe sécurisé.
def generate_password(length=20):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def main():
    parser = argparse.ArgumentParser(
        description="Gestionnaire de mots de passe chiffré avec GPG"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande init
    init_parser = subparsers.add_parser('init', help='Initialiser le magasin de mots de passe')
    init_parser.add_argument(
        'email',
        help='Adresse email associée à la clé GPG'
    )
    init_parser.add_argument(
        '-f', '--force',
        action='store_true',
        help='Forcer la réinitialisation même si déjà initialisé'
    )
    
    # Commande add
    add_parser = subparsers.add_parser('add', help='Ajouter un nouveau mot de passe')
    add_parser.add_argument(
        'name',
        help='Nom/identifiant du mot de passe (ex: gmail, facebook, netflix)'
    )
    add_parser.add_argument(
        '-g', '--generate',
        action='store_true',
        help='Générer automatiquement un mot de passe sécurisé'
    )
    add_parser.add_argument(
        '-l', '--length',
        type=int,
        default=20,
        help='Longueur du mot de passe généré (par défaut c\'est 20)'
    )
    add_parser.add_argument(
        '-u', '--username',
        help='Identifiant ou nom d\'utilisateur'
    )
    add_parser.add_argument(
        '--url',
        help='URL du site web'
    )

    # Commande delete
    delete_parser = subparsers.add_parser('delete', help='Supprimer un mot de passe')
    delete_parser.add_argument(
        'name',
        help='Nom/identifiant du mot de passe à supprimer'
    )

    # Commande edit 
    edit_parser = subparsers.add_parser('edit', help='Modifier un mot de passe existant')
    edit_parser.add_argument(
        'name',
        help='Nom/identifiant du mot de passe à modifier'
    )
    edit_parser.add_argument(
        '-u', '--username',
        help='Identifiant ou nom d\'utilisateur'
    )
    edit_parser.add_argument(
        '--url',
        help='URL du site web'
    )
    
    #Commande show
    show_parser = subparsers.add_parser('show', help='Afficher un mot de passe existant')
    show_parser.add_argument(
        'name',
        help='Nom/identifiant du mot de passe à afficher'
    )
    show_parser.add_argument(
        '-c', '--copy',
        action='store_true',
        help='Copier le mot de passe dans le presse-papiers'
    )
    
    # Commande list
    list_parser = subparsers.add_parser('list', help='Lister tous les mots de passe')
    list_parser.add_argument(
        '-s', '--search',
        help='Rechercher un mot de passe par nom'
    )
    
    args = parser.parse_args()
    
    # Exécution des commandes
    if args.command == 'init':
        init_password_store(args.email, force=args.force)
    elif args.command == 'add':
        add_password(args.name, length=args.length, generate=args.generate, 
                    username=args.username, url=args.url)
    elif args.command == 'delete':
        delete_password(args.name)
    elif args.command == 'edit':
        edit_password(args.name, username=args.username, url=args.url)
    elif args.command == 'show':
        show_password(args.name, copy=args.copy)
    elif args.command == 'list':
        list_passwords(search=args.search)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()


