"""Base de connaissances — charge knowledge/*.md et sélectionne les sections pertinentes.

Principe : on ne jette PAS tout le fichier dans le contexte (trop volumineux).
On découpe par sections (##) et on sélectionne celles dont les mots-clés
correspondent au prompt utilisateur.
"""
import logging
import os
import re
from typing import Dict, List

logger = logging.getLogger("cyberai.knowledge")


class KnowledgeBase:
    def __init__(self, dossier: str = "knowledge"):
        self.dossier = dossier
        self.sections: List[Dict] = []
        self._charger()

    def _charger(self) -> None:
        if not os.path.isdir(self.dossier):
            logger.warning(f"Dossier de connaissances introuvable : {self.dossier}")
            return
        for nom in sorted(os.listdir(self.dossier)):
            if not nom.endswith(".md"):
                continue
            chemin = os.path.join(self.dossier, nom)
            try:
                with open(chemin, encoding="utf-8") as f:
                    texte = f.read()
            except Exception as e:
                logger.warning(f"Impossible de lire {chemin} : {e}")
                continue
            # Découper par en-têtes de niveau 2
            blocs = re.split(r"\n## ", texte)
            for bloc in blocs:
                bloc = bloc.strip()
                if not bloc:
                    continue
                titre = bloc.splitlines()[0].strip()
                mots = set(re.findall(r"[a-z0-9_-]{3,}", titre.lower()))
                mots.update(re.findall(r"cve-\d{4}-\d+", bloc.lower()))
                self.sections.append({
                    "titre": titre,
                    "mots": mots,
                    "contenu": "## " + bloc,
                    "fichier": nom,
                })
        logger.info(f"✅ {len(self.sections)} sections de connaissances chargées depuis {self.dossier}/")

    def selectionner(self, prompt: str, max_chars: int = 5000) -> str:
        """Retourne les sections les plus pertinentes pour le prompt (max_chars caractères)."""
        if not self.sections:
            return ""
        p = prompt.lower()
        mots_prompt = set(re.findall(r"[a-z0-9_-]{3,}", p))
        cves_prompt = re.findall(r"cve-\d{4}-\d+", p)

        scores = []
        for s in self.sections:
            score = len(mots_prompt & s["mots"])
            for cve in cves_prompt:
                if cve in s["contenu"].lower():
                    score += 10  # une CVE exacte matche TOUJOURS sa section
            if score > 0:
                scores.append((score, s["contenu"]))

        scores.sort(key=lambda x: -x[0])
        out, total = [], 0
        for _, contenu in scores:
            if total + len(contenu) > max_chars:
                continue
            out.append(contenu)
            total += len(contenu)
        return "\n\n".join(out)