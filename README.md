# 🛡️ Veillia

**Veillia** est une plateforme de sensibilisation et d'entraînement à la cybersécurité conçue pour aider les entreprises à réduire le risque humain face aux attaques de phishing et d'ingénierie sociale.

La plateforme combine **Machine Learning**, **IA générative**, **gamification** et **formation adaptative** afin de transformer chaque incident potentiel en opportunité d'apprentissage.

---

# 🎯 Objectif

Les solutions traditionnelles se concentrent principalement sur le blocage des menaces.

Veillia se concentre sur le facteur humain.

Notre mission est simple :

> Détecter, expliquer, former et améliorer le comportement des utilisateurs face aux menaces cyber.

---

# 🚀 Fonctionnalités

## 🔍 Détection intelligente des menaces

### Analyse hybride ML + IA

Veillia utilise une architecture hybride :

```text
Email / URL
        ↓
Feature Extractor
        ↓
Machine Learning
        ↓
Analyse IA Contextuelle
        ↓
Fusion des résultats
        ↓
Décision finale
```

Cette approche permet :

* Une analyse rapide grâce aux modèles locaux
* Une compréhension contextuelle grâce à l'IA
* Une meilleure transparence des décisions

---

## 🧠 Détection des techniques d'ingénierie sociale

L'IA identifie automatiquement :

* Urgence
* Autorité
* Peur
* Curiosité
* Rareté
* Fraude au Président (BEC)
* Spear Phishing
* Credential Harvesting

---

## 🎓 Formation adaptative

Après chaque analyse :

* Explication pédagogique de la menace
* Recommandation automatique de formations
* Parcours d'apprentissage personnalisés

Exemple :

```text
Menace détectée : Fraude au Président

→ Formation recommandée :
   Détecter les demandes de virement frauduleuses

→ Formation complémentaire :
   Reconnaître les techniques de manipulation psychologique
```

---

## 🏆 Gamification

Pour maximiser l'engagement des collaborateurs :

* XP
* Niveaux
* Vigilance Score
* Classements
* Défis de sensibilisation

---

## ❓ Quiz intelligents

Veillia génère automatiquement des quiz à partir des menaces analysées.

Objectif :

* Renforcer l'apprentissage
* Mesurer la compréhension
* Améliorer le Vigilance Score

---

## 📊 Dashboard Administrateur

Les responsables sécurité disposent d'une vue globale :

* Risque moyen de l'entreprise
* Départements les plus exposés
* Utilisateurs à risque
* Progression des formations
* Taux de réussite aux quiz
* Historique des simulations phishing

---

## ⚠️ Engine Disagreement

Veillia expose les divergences entre les moteurs d'analyse.

Exemple :

```json
{
  "ml_score": 52,
  "llm_score": 91,
  "engine_disagreement": true
}
```

Cette transparence permet aux équipes sécurité de mieux comprendre les cas complexes.

---

# 🏗️ Architecture

## Backend

* FastAPI
* SQLAlchemy
* Alembic
* JWT Authentication
* WebSockets

## Frontend

* React
* TypeScript
* Vite

## Intelligence Artificielle

### Machine Learning

* Détection de phishing
* Détection d'URLs malveillantes
* Classification automatique

### IA Générative

* Analyse contextuelle
* Explications pédagogiques
* Classification des attaques
* Recommandations de formation
* Génération de quiz

---

# 🔒 Sécurité & Confidentialité

Veillia adopte une approche "Privacy by Design".

Les contenus analysés sont transformés en caractéristiques de sécurité avant traitement IA :

```text
Email
    ↓
Extraction de Features
    ↓
Analyse IA
```

Cette approche :

* Réduit les coûts d'analyse
* Limite l'exposition des données
* Améliore les performances

---

# 📈 Vision

Veillia n'est pas simplement un détecteur de phishing.

La plateforme évolue vers un système de :

### Cyber-Coaching Adaptatif

```text
Menace détectée
        ↓
Analyse
        ↓
Explication
        ↓
Formation
        ↓
Quiz
        ↓
Amélioration du comportement
```

L'objectif final est de réduire durablement le risque humain au sein des organisations.

---

# 🛠️ Installation

## Backend

```bash
git clone https://github.com/your-org/veillia.git

cd backend

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

## Frontend

```bash
cd frontend

npm install

npm run dev
```

---

# 📄 Licence

Projet développé dans un cadre éducatif et de recherche.

Tous droits réservés.
