import re
from dataclasses import dataclass, asdict
from typing import Dict, List


URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>()]*)?"
)


@dataclass
class EmailFeatures:
    content_length: int
    url_count: int
    has_url: bool
    urgency_count: int
    authority_count: int
    reward_count: int
    brand_count: int
    credential_count: int
    has_attachment_reference: bool
    has_money_reference: bool
    has_reply_request: bool
    urls: List[str]
    techniques: List[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class FeatureExtractor:
    urgency_words = [
        "urgent",
        "immediat",
        "immediate",
        "immédiat",
        "immédiate",
        "vite",
        "rapidement",
        "24h",
        "maintenant",
        "action requise",
        "dernier avertissement",
        "suspendu",
        "bloque",
        "bloqué",
    ]
    authority_words = [
        "ceo",
        "directeur",
        "direction",
        "president",
        "président",
        "rh",
        "drh",
        "dsi",
        "admin",
        "support",
        "service informatique",
    ]
    reward_words = [
        "cadeau",
        "gagner",
        "prix",
        "gratuit",
        "recompense",
        "récompense",
        "selectionne",
        "sélectionné",
        "chanceux",
        "felicitations",
        "félicitations",
    ]
    brand_words = [
        "amazon",
        "microsoft",
        "paypal",
        "netflix",
        "ameli",
        "fedex",
        "chronopost",
        "lidl",
        "banque",
        "office365",
    ]
    credential_words = [
        "mot de passe",
        "identifiant",
        "connexion",
        "login",
        "verifier votre compte",
        "vérifier votre compte",
        "mettre a jour",
        "mettre à jour",
        "confirmer vos informations",
    ]
    attachment_words = ["piece jointe", "pièce jointe", "facture", "document", "pdf", "invoice"]
    money_words = ["virement", "paiement", "iban", "facture", "remboursement", "transaction", "argent"]
    extortion_words = [
        "divulgue",
        "divulguer",
        "publie",
        "publier",
        "expose",
        "exposer",
        "chantage",
        "rancon",
        "rançon",
        "sinon",
        "menace",
    ]
    adult_or_hacking_words = [
        "porn",
        "xxx",
        "sex",
        "cam",
        "casino",
        "hack",
        "crack",
        "warez",
        "torrent",
        "freegift",
        "giveaway",
        "bonus",
    ]
    reply_words = ["repondez", "répondez", "reply", "envoyez-moi", "confirmez par retour"]

    def extract(self, content: str) -> EmailFeatures:
        text_lower = content.lower()
        urls = URL_PATTERN.findall(content)

        urgency_count = self._count_matches(text_lower, self.urgency_words)
        authority_count = self._count_matches(text_lower, self.authority_words)
        reward_count = self._count_matches(text_lower, self.reward_words)
        brand_count = self._count_matches(text_lower, self.brand_words)
        credential_count = self._count_matches(text_lower, self.credential_words)

        techniques = []
        if urgency_count:
            techniques.append("Urgency")
        if authority_count:
            techniques.append("Authority")
        if reward_count:
            techniques.append("Reward bait")
        if brand_count:
            techniques.append("Brand impersonation")
        if credential_count:
            techniques.append("Credential harvesting")
        if urls:
            techniques.append("Suspicious link")
        if self._has_any(text_lower, self.extortion_words):
            techniques.append("Extortion")
        if self._has_any(text_lower, self.adult_or_hacking_words):
            techniques.append("High-risk content")

        return EmailFeatures(
            content_length=len(content),
            url_count=len(urls),
            has_url=bool(urls),
            urgency_count=urgency_count,
            authority_count=authority_count,
            reward_count=reward_count,
            brand_count=brand_count,
            credential_count=credential_count,
            has_attachment_reference=self._has_any(text_lower, self.attachment_words),
            has_money_reference=self._has_any(text_lower, self.money_words),
            has_reply_request=self._has_any(text_lower, self.reply_words),
            urls=urls,
            techniques=techniques,
        )

    @staticmethod
    def _has_any(text: str, words: List[str]) -> bool:
        return any(word in text for word in words)

    @staticmethod
    def _count_matches(text: str, words: List[str]) -> int:
        return sum(1 for word in words if word in text)
