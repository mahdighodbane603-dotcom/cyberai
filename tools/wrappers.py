"""Exécution de vrais outils de pentest via subprocess.

Si l'outil n'est pas installé, on renvoie les commandes du snippet au lieu d'inventer.
"""
import logging
import shutil
import subprocess
from typing import List

logger = logging.getLogger("cyberai.tools.wrappers")


class ToolRunner:
    """Lance les outils réels et retourne leur sortie brute."""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def _run(self, cmd: List[str]) -> str:
        """Exécute une commande et retourne la sortie (limitée à 6000 caractères)."""
        if not shutil.which(cmd[0]):
            return (f"⚠️ L'outil '{cmd[0]}' n'est pas installé sur cette machine.\n"
                    f"Commande prévue : {' '.join(cmd)}\n"
                    f"→ Installe-le (voir notes) ou exécute-la sur ta machine d'attaque.")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
            sortie = result.stdout or result.stderr
            return sortie[:6000] or "(aucune sortie)"
        except subprocess.TimeoutExpired:
            return f"⏱️ Timeout après {self.timeout}s — commande interrompue."
        except Exception as e:
            return f"⚠️ Erreur d'exécution : {e}"

    # --- outils individuels ---
    def nmap_scan(self, cible: str, args: str = "-sV -sC") -> str:
        return self._run(["nmap", *args.split(), cible])

    def sqlmap(self, url: str, args: str = "--batch --level=1") -> str:
        return self._run(["sqlmap", "-u", url, *args.split()])

    def searchsploit(self, terme: str) -> str:
        return self._run(["searchsploit", terme])

    def curl_headers(self, url: str) -> str:
        return self._run(["curl", "-sI", url])