# Application d'Authentification Simple

Une application web Node.js/Express montrant des exemples de vulnérabilités Security Misconfiguration et Insecure Design.

## 📋 Description

Cette application présente un système d'authentification simple avec :
- Connexion utilisateur et administrateur
- Gestion des sessions
- Réinitialisation de mot de passe
- Pages distinctes selon les rôles

La version vulnérable est présente sur la branche `main` et la version corrigée sur la branche `fix`.

## 🚀 Installation

> [!WARNING]
> Le projet requiert d'avoir une version de Node.js <= 20 !

1. Clonez le projet et naviguez dans le dossier
2. Installez les dépendances :
   ```bash
   npm install
   ```

3. Configurez les variables d'environnement :
   ```bash
   cp .env.example .env
   ```
   Éditez le fichier `.env` et définissez :
   ```
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=motdepasse_admin
   ```

## 🔧 Utilisation

Démarrez l'application :
```bash
npm start
```

L'application sera accessible sur `http://localhost:3000`

## 👤 Comptes par défaut

- **Utilisateur** : `user1` / `password1`
- **Administrateur** : Défini dans le fichier `.env`

## 🔗 Routes disponibles

- `/` - Page d'accueil (redirection automatique)
- `/login` - Page de connexion
- `/user` - Espace utilisateur
- `/admin` - Espace administrateur
- `/reset-password` - Réinitialisation de mot de passe
- `/logout` - Déconnexion
- `/debug` - Informations de debug

## 📁 Structure

```
├── app.js              # Serveur principal
├── package.json        # Configuration npm
├── views/              # Templates HTML
│   ├── login.html
│   ├── user.html
│   ├── admin.html
│   └── reset-password.html
└── .env.example        # Variables d'environnement exemple
```

## ⚙️ Technologies

- **Node.js** - Runtime JavaScript
- **Express** - Framework web
- **better-sqlite3** - Base de données SQLite
- **express-session** - Gestion des sessions
