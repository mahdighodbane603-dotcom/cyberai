"""Stockage persistant des conversations (fichier JSON).

Chaque conversation a un id, un titre, et une liste de messages.
Tout est sauvegardé sur disque à chaque message : rien ne se perd
au redémarrage du serveur.
"""
import json
import os
import time
import uuid
from typing import Dict, List, Optional


class ConversationStore:
    def __init__(self, chemin: str = "data/conversations.json"):
        self.chemin = chemin
        self._data: Dict = {"conversations": {}}
        self._charger()

    def _charger(self) -> None:
        if os.path.isfile(self.chemin):
            try:
                with open(self.chemin, encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {"conversations": {}}

    def _sauver(self) -> None:
        os.makedirs(os.path.dirname(self.chemin), exist_ok=True)
        with open(self.chemin, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    # ---------- CRUD ----------
    def creer(self, titre: str = "Nouvelle conversation") -> str:
        cid = uuid.uuid4().hex[:12]
        self._data["conversations"][cid] = {
            "id": cid,
            "titre": titre,
            "created_at": time.time(),
            "updated_at": time.time(),
            "messages": [],
        }
        self._sauver()
        return cid

    def lister(self) -> List[Dict]:
        convs = list(self._data["conversations"].values())
        convs.sort(key=lambda c: c["updated_at"], reverse=True)
        return [
            {
                "id": c["id"],
                "titre": c["titre"],
                "updated_at": c["updated_at"],
                "nb_messages": len(c["messages"]),
            }
            for c in convs
        ]

    def get(self, cid: str) -> Optional[Dict]:
        return self._data["conversations"].get(cid)

    def supprimer(self, cid: str) -> bool:
        if cid in self._data["conversations"]:
            del self._data["conversations"][cid]
            self._sauver()
            return True
        return False

    # ---------- Messages ----------
    def ajouter_message(self, cid: str, role: str, contenu: str) -> bool:
        conv = self._data["conversations"].get(cid)
        if not conv:
            return False
        conv["messages"].append(
            {"role": role, "content": contenu, "time": time.time()}
        )
        conv["updated_at"] = time.time()
        # Titre auto : premier message utilisateur tronqué
        if len(conv["messages"]) == 1 and conv["titre"] == "Nouvelle conversation":
            t = contenu.replace("\n", " ").strip()[:60]
            conv["titre"] = t + ("..." if len(contenu) > 60 else "")
        self._sauver()
        return True

    def historique_llm(self, cid: str, max_messages: int = 8) -> List[Dict]:
        """Derniers messages au format OpenAI, pour le contexte Groq."""
        conv = self._data["conversations"].get(cid)
        if not conv:
            return []
        msgs = [{"role": m["role"], "content": m["content"]} for m in conv["messages"]]
        return msgs[-max_messages:]