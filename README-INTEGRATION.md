# Veillia — Guide d'intégration Frontend ↔ Backend

## Prérequis
```Prérequis : 
Python : 3.11.9
Node.js
```

## Démarrage en développement

### 1. Backend (FastAPI)

```bash
cd Veillia-Backend

python -m venv venv
.\venv\Scripts\activate (sur Windows) ou source venv/bin/activate (sur Linux)

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend (Vite + React)

```bash
cd Veillia-Frontend

npm install
npm run dev
```

Le frontend sera disponible sur **http://localhost:5173** et communiquera avec le backend via le proxy Vite.

.\venv\Scripts\alembic.exe upgrade head

.\venv\Scripts\python.exe create_admin.py