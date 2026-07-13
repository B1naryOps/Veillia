import re
import numpy as np
import joblib
from typing import Optional
from urllib.parse import urlparse
from fastapi import Request
from app.database import SessionLocal
from app.models.ml_analysis import MLAnalysis
from app.core.audit import log_audit
from app.ml.loader import nlp_pipeline, url_model, url_scaler, url_features_list
from app.ml.feature_extractor import FeatureExtractor
from app.ml.llm_advisor import LLMAdvisor


feature_extractor = FeatureExtractor()
llm_advisor = LLMAdvisor()


def _normalize_url(url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return "http://" + url


def _assess_url_risk(url: str):
    normalized = _normalize_url(url.strip(".,;:!?)]}"))
    parsed = urlparse(normalized)
    host = (parsed.netloc or parsed.path).lower()
    path = (parsed.path or "").lower()
    full = normalized.lower()
    score = 0.45
    reasons = []

    trusted_domains = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "netflix.com",
        "ameli.fr",
        "service-public.fr",
        "gouv.fr",
    ]
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "cutt.ly", "is.gd", "lnkd.in"]
    risky_tlds = [".zip", ".mov", ".top", ".xyz", ".click", ".quest", ".rest", ".cam", ".porn", ".xxx", ".sex"]
    risky_words = [
        "porn",
        "xxx",
        "sex",
        "casino",
        "hack",
        "crack",
        "warez",
        "torrent",
        "login",
        "verify",
        "secure",
        "account",
        "gift",
        "free",
        "bonus",
        "prize",
    ]

    if not host or "." not in host:
        reasons.append("**Lien invalide ou incomplet** : Le lien ne ressemble pas à un domaine officiel vérifiable.")
        score = max(score, 0.70)
    if any(host == domain or host.endswith("." + domain) for domain in trusted_domains):
        score = min(score, 0.25)
    else:
        reasons.append("**Domaine non reconnu** : Le lien ne correspond pas à une source de confiance connue par l'analyseur.")
        score = max(score, 0.55)
    if any(shortener in host for shortener in shorteners):
        reasons.append("**Lien raccourci** : Les raccourcisseurs masquent la destination réelle.")
        score = max(score, 0.75)
    if any(host.endswith(tld) for tld in risky_tlds):
        reasons.append("**Extension de domaine à risque** : Cette extension est souvent utilisée dans des campagnes douteuses.")
        score = max(score, 0.78)
    if any(word in host or word in path for word in risky_words):
        reasons.append("**Contenu ou mot-clé à risque** : Le lien contient des termes fréquemment associés à des pages malveillantes ou abusives.")
        score = max(score, 0.82)
    if "@" in full:
        reasons.append("**Camouflage d'URL** : Le lien contient un caractère @, souvent utilisé pour tromper sur la destination.")
        score = max(score, 0.85)
    if host.count(".") >= 3:
        reasons.append("**Sous-domaines multiples** : L'adresse utilise une structure complexe qui peut imiter un site légitime.")
        score = max(score, 0.68)
    if "-" in host and any(brand in host for brand in ["amazon", "paypal", "microsoft", "netflix", "ameli", "bank", "banque"]):
        reasons.append("**Imitation de marque dans le domaine** : Le lien mélange une marque connue avec un domaine non officiel.")
        score = max(score, 0.86)

    return score, reasons


def build_training_quiz(attack_type: str, techniques=None):
    techniques = techniques or []
    quizzes = {
        "CEO Fraud": {
            "question": "Quel est le bon réflexe face à une demande urgente de virement venant d'un dirigeant ?",
            "options": [
                "Vérifier la demande par un autre canal avant d'agir",
                "Faire le virement rapidement pour respecter l'urgence",
                "Répondre au message avec les informations demandées",
            ],
            "correct_answer": "Vérifier la demande par un autre canal avant d'agir",
        },
        "Extortion Scam": {
            "question": "Que faut-il faire face à une menace de divulgation contre de l'argent ?",
            "options": [
                "Ne pas payer, conserver les preuves et signaler",
                "Payer rapidement pour éviter le problème",
                "Répondre pour négocier avec l'expéditeur",
            ],
            "correct_answer": "Ne pas payer, conserver les preuves et signaler",
        },
        "Credential Phishing": {
            "question": "Quel signal doit te faire douter d'une demande de mot de passe ou de code ?",
            "options": [
                "Une demande urgente de validation ou de connexion",
                "La présence d'une formule de politesse",
                "Un message court",
            ],
            "correct_answer": "Une demande urgente de validation ou de connexion",
        },
        "Link Phishing": {
            "question": "Que faire avant de cliquer sur un lien inconnu ou raccourci ?",
            "options": [
                "Inspecter le domaine et passer par le site officiel",
                "Cliquer pour voir si la page semble correcte",
                "Partager le lien à un collègue pour qu'il teste",
            ],
            "correct_answer": "Inspecter le domaine et passer par le site officiel",
        },
        "High-Risk Link": {
            "question": "Pourquoi un lien avec des termes adultes, hacking ou bonus gratuit est-il risqué ?",
            "options": [
                "Il peut mener à des pages piégées ou à des publicités malveillantes",
                "Il est forcément bloqué par le navigateur",
                "Il est toujours officiel s'il commence par https",
            ],
            "correct_answer": "Il peut mener à des pages piégées ou à des publicités malveillantes",
        },
        "Brand Impersonation": {
            "question": "Quel réflexe adopter quand une marque connue promet un cadeau ou une récompense ?",
            "options": [
                "Vérifier depuis le site officiel de la marque",
                "Cliquer vite avant la fin de l'offre",
                "Envoyer ses informations pour confirmer l'éligibilité",
            ],
            "correct_answer": "Vérifier depuis le site officiel de la marque",
        },
        "Invoice Fraud": {
            "question": "Que faire si vous recevez une facture inattendue par email avec une demande de paiement ?",
            "options": [
                "Vérifier auprès du fournisseur par un numéro de téléphone connu avant de payer",
                "Payer immédiatement pour éviter des pénalités de retard",
                "Ignorer le message sans faire de vérification",
            ],
            "correct_answer": "Vérifier auprès du fournisseur par un numéro de téléphone connu avant de payer",
        },
    }

    quiz = quizzes.get(
        attack_type,
        {
            "question": "Quel est le meilleur réflexe face à un message inattendu ?",
            "options": [
                "Prendre le temps de vérifier l'expéditeur, le contexte et les liens",
                "Répondre rapidement pour éviter un retard",
                "Cliquer sur les liens pour comprendre la demande",
            ],
            "correct_answer": "Prendre le temps de vérifier l'expéditeur, le contexte et les liens",
        },
    )
    return {
        "attack_type": attack_type,
        "question": quiz["question"],
        "options": quiz["options"],
        "xp_reward": 25,
        "vigilance_reward": 3,
    }


def get_quiz_correct_answer(attack_type: str):
    quiz = build_training_quiz(attack_type)
    lookup = {
        "CEO Fraud": "Vérifier la demande par un autre canal avant d'agir",
        "Extortion Scam": "Ne pas payer, conserver les preuves et signaler",
        "Credential Phishing": "Une demande urgente de validation ou de connexion",
        "Link Phishing": "Inspecter le domaine et passer par le site officiel",
        "High-Risk Link": "Il peut mener à des pages piégées ou à des publicités malveillantes",
        "Brand Impersonation": "Vérifier depuis le site officiel de la marque",
        "Invoice Fraud": "Vérifier auprès du fournisseur par un numéro de téléphone connu avant de payer",
    }
    return lookup.get(attack_type, quiz["options"][0])

def extract_url_features(url):
    """Extrait les caractéristiques numériques d'une URL pour le modèle URL."""
    if not url_features_list:
        return None
        
    features = {
        "NumDots": url.count('.'),
        "SubdomainLevel": max(0, url.count('.') - 1),
        "PathLevel": url.count('/'),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "AtSymbol": 1 if '@' in url else 0,
        "TildeSymbol": 1 if '~' in url else 0,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": url.count('&') + url.count('?')
    }
    # Remplissage du vecteur selon l'ordre des colonnes du CSV
    vector = [features.get(col, 0) for col in url_features_list]
    return np.array(vector).reshape(1, -1)

def analyze_text_ml(content: str, features=None):
    reasons = []
    text_lower = content.lower()
    if features is None:
        features = feature_extractor.extract(content)
    
    # --- 1. Analyse NLP ---
    prob_nlp = 0.0
    if nlp_pipeline:
        prob_nlp = float(nlp_pipeline.predict_proba([content])[0][1])

    # --- 2. Heuristiques Spécifiques (Le filet de sécurité) ---
    
    gift_keywords = ["gagner", "prix exclusif", "coffret", "cadeau", "sélectionné", "chanceux", "gratuit", "récompense"]
    if any(word in text_lower for word in gift_keywords):
        match_count = sum(1 for word in gift_keywords if word in text_lower)
        if match_count >= 2:
            reasons.append("**Appât de gain** : Les promesses de cadeaux gratuits (outils, smartphones) sont souvent utilisées pour voler vos informations personnelles.")
            prob_nlp = max(prob_nlp, 0.85)

    # Détection d'Urgence
    urgency_words = ["immédiat", "urgent", "répondez simplement", "obtenez-le maintenant", "vite", "24h", "maintenant", "rapidement"]
    if any(word in text_lower for word in urgency_words):
        reasons.append("**Pression temporelle** : L'attaquant essaie de vous faire agir dans la précipitation pour que vous ne vérifiiez pas l'authenticité du message.")
        prob_nlp = max(prob_nlp, 0.70)

    extortion_words = ["argent", "divulgue", "divulguer", "publie", "publier", "chantage", "rancon", "rançon", "sinon", "menace"]
    if any(word in text_lower for word in extortion_words):
        reasons.append("**Menace ou chantage** : Le message tente de vous pousser à payer ou agir sous la menace de divulgation d'informations.")
        prob_nlp = max(prob_nlp, 0.85)

    authority_words = ["ceo", "directeur", "direction", "président", "president", "drh", "dsi"]
    money_words = ["virement", "paiement", "iban", "facture", "transaction", "argent"]
    if any(word in text_lower for word in authority_words) and any(word in text_lower for word in money_words):
        reasons.append("**Fraude au dirigeant** : Le message combine une autorité hiérarchique et une demande financière, un schéma classique de CEO fraud.")
        prob_nlp = max(prob_nlp, 0.88)

    credential_words = ["mot de passe", "identifiant", "connexion", "login", "code", "otp", "compte", "confirme", "valide", "vérifie", "verifie"]
    action_words = ["envoie", "envoyez", "fais", "clique", "ouvre", "connecte", "confirme", "valide", "paie", "paye"]
    if len(content.strip()) <= 90:
        if any(word in text_lower for word in money_words) and any(word in text_lower for word in urgency_words + action_words):
            reasons.append("**Demande courte à risque** : Le message est bref mais combine une action demandée et un enjeu financier.")
            prob_nlp = max(prob_nlp, 0.76)
        if any(word in text_lower for word in credential_words) and any(word in text_lower for word in urgency_words + action_words):
            reasons.append("**Demande d'identifiants** : Le message court pousse à valider ou transmettre des informations sensibles.")
            prob_nlp = max(prob_nlp, 0.78)
        if any(word in text_lower for word in authority_words) and any(word in text_lower for word in urgency_words + action_words):
            reasons.append("**Autorité + action rapide** : Le message utilise une position d'autorité pour obtenir une action immédiate.")
            prob_nlp = max(prob_nlp, 0.72)

    # Détection de l'Usurpation de marque
    brands = ["lidl", "amazon", "makita", "samsung", "iphone", "ameli", "banque"]
    if any(b in text_lower for b in brands) and any(g in text_lower for g in gift_keywords):
        reasons.append("**Usurpation d'identité** : Le message utilise le nom d'une marque connue pour gagner votre confiance.")
        prob_nlp = max(prob_nlp, 0.90)

    # 2. Analyse technique des URLs
    prob_url = 0.0
    urls = features.urls

    if urls:
        heuristic_url_scores = []
        for url in urls:
            url_score, url_reasons = _assess_url_risk(url)
            heuristic_url_scores.append(url_score)
            for reason in url_reasons:
                if reason not in reasons:
                    reasons.append(reason)
        prob_url = max(prob_url, max(heuristic_url_scores) if heuristic_url_scores else 0.0)
        if prob_url >= 0.55 and not any("Lien suspect" in reason for reason in reasons):
            reasons.append("**Lien suspect** : L'adresse doit être vérifiée avant tout clic, surtout si elle arrive sans contexte fiable.")

    if urls and url_model and url_scaler:
        url_probs = []
        for url in urls:
            normalized_url = _normalize_url(url)
            feat = extract_url_features(normalized_url)
            if feat is not None:
                feat_scaled = url_scaler.transform(feat)
                p = float(url_model.predict_proba(feat_scaled)[0][1])
                url_probs.append(p)
                
                cloud_services = ["googleapis.com", "s3.amazonaws.com", "windows.net", "pages.dev", "firebaseapp.com"]
                if any(service in normalized_url for service in cloud_services):
                    reasons.append("**Hébergement Cloud suspect** : Ce lien utilise un service de stockage légitime (Google/Azure) pour masquer une page frauduleuse. C'est une technique très courante en phishing.")
                    p = max(p, 0.80) # On augmente la probabilité

                if len(normalized_url.split('#')[-1]) > 30 or len(normalized_url.split('?')[-1]) > 30:
                    reasons.append("**Paramètres de suivi détectés** : Le lien contient des identifiants encodés. Les pirates utilisent cela pour savoir quel employé a cliqué sur le lien.")
                    p = max(p, 0.75)

                if normalized_url.endswith(".html") or ".html?" in normalized_url or ".html#" in normalized_url:
                    if any(x in normalized_url.lower() for x in ["login", "verify", "secure", "href"]):
                        reasons.append("**Page de formulaire suspecte** : Le lien dirige vers un fichier HTML isolé, souvent utilisé pour afficher de faux formulaires de connexion.")
                
                url_probs[-1] = p 

        prob_url = max(prob_url, max(url_probs) if url_probs else 0.0)

    # 3. Score Final
    final_prob = max(prob_nlp, prob_url)
    is_phishing = final_prob >= 0.5
    confidence = round(final_prob * 100, 2)

    if not reasons:
        reasons.append("Aucun indicateur de menace majeur détecté.")

    ml_score = round(final_prob * 100)
    llm_result = llm_advisor.analyze(content, features)
    llm_score = int(llm_result["llm_score"])

    return {
        "is_phishing": is_phishing,
        "probability": round(final_prob, 4),
        "confidence": confidence,
        "ml_score": ml_score,
        "llm_score": llm_score,
        "final_score": ml_score,
        "decision_source": "ml",
        "engine_disagreement": abs(ml_score - llm_score) >= 25,
        "features": features.to_dict(),
        "explanation": reasons
        + ([llm_result["llm_explanation"]] if llm_result.get("llm_explanation") else []),
        "attack_type": llm_result["attack_type"],
        "techniques": llm_result["techniques"],
        "recommended_training": llm_result["recommended_training"],
        "quiz": build_training_quiz(llm_result["attack_type"], llm_result["techniques"]),
    }

async def save_analysis_and_audit(text: str, request: Request, user_id: Optional[int] = None):
    """Réalise l'analyse, l'enregistre en base et crée un log d'audit."""
    
    # Phase 1: Email -> FeatureExtractor -> ML -> Classification -> LLM advisor.
    features = feature_extractor.extract(text)
    result = analyze_text_ml(text, features=features)

    # Sauvegarde dans la table ml_analysis
    async with SessionLocal() as db:
        analysis = MLAnalysis(
            user_id=user_id,
            content=text,
            is_phishing=result["is_phishing"],
            probability=result["probability"],
            confidence=result["confidence"]
        )
        db.add(analysis)
        await db.commit()

    # Log d'audit pour la traçabilité
    await log_audit(
        user_id=user_id,
        action="ML_ANALYSIS_HYBRID",
        endpoint=str(request.url.path),
        method=request.method,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("User-Agent", "unknown"),
        status_code=200
    )
    
    return result
