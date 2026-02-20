# CheckMatin

**CheckMatin** est une extension pour **Chrome** et **Firefox** qui automatise la vérification de vos sites web (statut, contenu, captures d'écran) et génère des rapports de recette instantanés.

---

## 🚀 Fonctionnalités Principales

### 1. Vérifications Automatisées
Pour chaque site configuré, l'extension effectue les actions suivantes :
- **Status HTTP** : Vérifie que le site répond correctement (Code 200).
- **Vérification de Contenu** : Cherche un texte spécifique dans la page pour s'assurer qu'elle s'est chargée correctement (ex: "Bienvenue", "Copyright").
- **Vérification de Date** : S'assure que la page est à jour en cherchant la date du jour ou une date spécifique.
- **Capture d'écran Complète** : Capture **toute la hauteur de la page** (pas seulement la zone visible) grâce à une technologie de défilement intelligent ("Scroll & Stitch").

### 2. Gestion de l'Authentification
- Supporte les sites nécessitant une connexion (Login / Mot de passe).
- Gère automatiquement les redirections post-login.
- **Validation Manuelle** : Pour les sites avec 2FA (Double facteur) ou Google Auth, l'extension met le test en pause, vous laisse vous connecter manuellement, puis reprend la vérification.

### 3. Sécurité & Confidentialité
- **Mot de Passe Maître** : Vos identifiants de sites sont chiffrés (AES-256) et protégés par un mot de passe maître unique.
- **Données Locales** : Tout reste sur votre machine. Aucune donnée n'est envoyée vers un serveur tiers.

### 4. Rapports & Partage
- **Rapport HTML Riche** : Génère un rapport visuel incluant les statuts (OK/Erreur), les logs détaillés et les miniatures des captures d'écran.
- **Copie Presse-papier** : Copiez le rapport en un clic pour le coller directement dans un email (Gmail, Outlook...) ou un ticket.
- **Export/Import** : Sauvegardez votre configuration (avec ou sans mots de passe) pour la partager avec votre équipe ou faire des backups.

---

## 📦 Installation

### Firefox
1. Téléchargez le fichier `.zip` ou le dossier `dist/firefox`.
2. Ouvrez Firefox et tapez `about:debugging` dans la barre d'adresse.
3. Cliquez sur **"Ce Firefox"** (à gauche).
4. Cliquez sur **"Charger un module complémentaire temporaire..."**.
5. Sélectionnez le fichier `manifest.json` dans le dossier `dist/firefox`.

### Chrome / Edge / Brave
1. Téléchargez le fichier `.zip` ou le dossier `dist/chrome`.
2. Ouvrez Chrome et tapez `chrome://extensions`.
3. Activez le **"Mode développeur"** (en haut à droite).
4. Cliquez sur **"Charger l'extension non empaquetée"**.
5. Sélectionnez le dossier `dist/chrome`.

---

## 🛠 Utilisation

1. Cliquez sur l'icône **CheckMatin** dans votre barre d'outils.
2. Ouvrez le **Tableau de Bord**.
3. Définissez votre **Mot de Passe Maître** (obligatoire pour sécuriser vos données).
4. Ajoutez vos sites via le bouton **"Ajouter un Site"**.
   - Renseignez l'URL, le nom, et les vérifications souhaitées.
   - Activez l'authentification si nécessaire.
5. Cliquez sur **"Lancer les Vérifications"**.
   - L'extension va ouvrir une fenêtre dédiée et passer les sites en revue un par un.
   - **Important** : Ne fermez pas la fenêtre de vérification pendant le processus.
6. Une fois terminé, utilisez les boutons **"Copier Rapport"** ou **"Télécharger Rapport"** pour exploiter les résultats.

---

## 📂 Structure du Projet (Pour les développeurs)

- `manifest_firefox.json` / `manifest_chrome.json` : Configuration des extensions.
- `options.html` / `options.js` : Interface principale et logique métier (Dashboard).
- `background.js` : Gestionnaire d'événements en arrière-plan (Service Worker).
- `assets/` : Icônes et ressources graphiques.
- `dist/` : Dossiers de compilation générés.

---

## 📄 Licence

Ce projet est sous licence **GNU General Public License v3.0**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

**Développé avec ❤️ pour simplifier vos matins.**
