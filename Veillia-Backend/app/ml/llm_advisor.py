from typing import Dict, List

from app.ml.feature_extractor import EmailFeatures


class LLMAdvisor:
    """Local Phase 1 advisor.

    This keeps the LLM role separate from the ML decision path: it produces
    explanations, an attack label, and training suggestions, but never decides
    whether the email is phishing.
    """

    def analyze(self, content: str, features: EmailFeatures) -> Dict[str, object]:
        score = self._score(features)
        attack_type = self._classify_attack(features)
        recommended_training = self._recommend_training(features)
        explanation = self._explain(features, attack_type)

        return {
            "llm_score": score,
            "attack_type": attack_type,
            "techniques": features.techniques,
            "recommended_training": recommended_training,
            "llm_explanation": explanation,
        }

    def _score(self, features: EmailFeatures) -> int:
        score = 0
        score += min(features.urgency_count * 18, 30)
        score += min(features.authority_count * 18, 25)
        score += min(features.reward_count * 16, 30)
        score += min(features.brand_count * 12, 20)
        score += min(features.credential_count * 18, 30)
        score += 15 if features.has_url else 0
        score += 35 if "High-risk content" in features.techniques else 0
        score += 10 if features.has_money_reference else 0
        score += 8 if features.has_attachment_reference else 0
        score += 6 if features.has_reply_request else 0
        if features.authority_count and features.has_money_reference:
            score += 35
        if "Extortion" in features.techniques and features.has_money_reference:
            score += 30
        return min(score, 100)

    def _classify_attack(self, features: EmailFeatures) -> str:
        if "Extortion" in features.techniques and features.has_money_reference:
            return "Extortion Scam"
        if "High-risk content" in features.techniques and features.has_url:
            return "High-Risk Link"
        if features.authority_count and (features.has_money_reference or features.has_reply_request):
            return "CEO Fraud"
        if features.credential_count and (features.brand_count or features.has_url):
            return "Credential Phishing"
        if features.reward_count and features.brand_count:
            return "Brand Impersonation"
        if features.has_attachment_reference and features.has_money_reference:
            return "Invoice Fraud"
        if features.has_url:
            return "Link Phishing"
        return "Unknown"

    def _recommend_training(self, features: EmailFeatures) -> List[str]:
        training = []
        if features.urgency_count:
            training.append("Identifier la pression temporelle")
        if features.authority_count:
            training.append("Vérifier les demandes venant de la direction")
        if features.credential_count:
            training.append("Protéger ses identifiants")
        if features.brand_count:
            training.append("Reconnaître l'usurpation de marque")
        if features.has_url:
            training.append("Inspecter les liens avant de cliquer")
        if "High-risk content" in features.techniques:
            training.append("Reconnaître les liens à risque élevé")
        if "Extortion" in features.techniques:
            training.append("Réagir aux menaces et tentatives de chantage")
        if not training:
            training.append("Bonnes pratiques de vigilance email")
        return training[:3]

    def _explain(self, features: EmailFeatures, attack_type: str) -> str:
        if attack_type == "Unknown":
            return "Aucun scénario d'attaque clair n'a été identifié par la couche d'explication."

        signals = ", ".join(features.techniques[:3]) if features.techniques else "signaux faibles"
        return f"Le message ressemble à {attack_type} à cause des signaux suivants : {signals}."
