"""Routeur de commandes — associe un prompt à l'outil local adapté.

Ordre de décision :
1. Snippets vérifiés (réponse locale exacte)
2. Générateurs (reverse shells, SQLi, SYN flood)
3. Outils réels (nmap, sqlmap, searchsploit via wrappers)
4. Sinon → le LLM répond
"""
import re
from typing import Optional

from tools.snippets import SnippetLibrary
from tools.wrappers import ToolRunner
from tools.dos_tools import SynFlood
from tools.reverse_shell_tools import ReverseShellGenerator
from tools.sql_tools import SQLInjector


class CommandRouter:
    def __init__(self):
        self.snippets = SnippetLibrary()
        self.runner = ToolRunner()
        self.revshell = ReverseShellGenerator()
        self.sqli = SQLInjector()

    # ---------- utilitaires d'extraction ----------
    @staticmethod
    def _extract_ip(texte: str) -> Optional[str]:
        m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", texte)
        return m.group(1) if m else None

    @staticmethod
    def _extract_port(texte: str, defaut: int = 80) -> int:
        m = re.search(r":(\d{1,5})\b", texte)
        return int(m.group(1)) if m else defaut

    @staticmethod
    def _extract_url(texte: str) -> Optional[str]:
        m = re.search(r"https?://[^\s\"']+", texte)
        return m.group(0) if m else None

    # ---------- routage ----------
    def route(self, prompt: str) -> Optional[str]:
        p = prompt.lower()

        # ========== 1. Snippets vérifiés ==========
        rep = self.snippets.match(prompt)
        if rep:
            return rep

        # ========== 2. Générateurs locaux ==========
        if "reverse shell" in p or "rev shell" in p:
            ip = self._extract_ip(prompt) or "ATTACKER_IP"
            port = self._extract_port(prompt, 4444)
            return self.revshell.all_variants(ip, port)

        if ("sql" in p or "sqli" in p) and any(
            k in p for k in ["payload", "inject", "cheatsheet", "sqli"]
        ):
            return self.sqli.full_cheatsheet()

        if "syn flood" in p:
            ip = self._extract_ip(prompt)
            if not ip:
                return "⚠️ Précise une cible : `syn flood 192.168.1.100:80`\n\n(Teste uniquement sur ton propre lab.)"
            port = self._extract_port(prompt, 80)
            duree = 15
            m = re.search(r"(\d+)\s*(s|sec|secondes?)", p)
            if m:
                duree = int(m.group(1))
            try:
                flooder = SynFlood(ip, port, threads=50)
                total = flooder.start(duree=duree)
                return (
                    f"## 🚀 SYN Flood exécuté\n\n"
                    f"- **Cible :** `{ip}:{port}`\n"
                    f"- **Durée :** {duree}s\n"
                    f"- **Paquets :** {total:,}\n"
                    f"- **Débit :** ~{total // max(duree, 1):,} pkt/s\n\n"
                    f"**Interprétation :** avec des IP source aléatoires, la cible remplit sa table "
                    f"de connexions SYN. Ce test est éducatif — lab uniquement.\n"
                    f"**Contre-mesures :** syn cookies, rate limiting, pare-feu."
                )
            except Exception as e:
                return (f"⚠️ Erreur d'exécution : {e}\n\n"
                        f"Vérifie que Npcap est installé (https://npcap.com) pour l'envoi de paquets sur Windows.")

        # ========== 3. Outils réels ==========
        if "nmap" in p or "scan de port" in p:
            ip = self._extract_ip(prompt)
            if ip:
                return f"## 🔍 Scan Nmap réel sur {ip}\n\n" + self.runner.nmap_scan(ip)
            return self.snippets.get("commandes nmap") or "Usage : `nmap 192.168.1.1`"

        if "sqlmap" in p:
            url = self._extract_url(prompt)
            if url:
                return f"## ⚡ sqlmap réel sur {url}\n\n" + self.runner.sqlmap(url)
            return self.snippets.get("tamper") or "Usage : `sqlmap http://cible/page.php?id=1`"

        if "hashcat" in p or "cracker un hash" in p:
            return self.snippets.get("hashcat")

        if "msfvenom" in p or "generer un payload" in p or "générer un payload" in p:
            return self.snippets.get("msfvenom")

        if "searchsploit" in p or "exploit db" in p:
            m = re.search(r"searchsploit\s+(.+)", p)
            if m:
                return "## 🔎 searchsploit réel\n\n" + self.runner.searchsploit(m.group(1).strip())
            return "Usage : `searchsploit apache 2.4.49` — je lance l'outil réel."

        # ========== 4. Rien de local → le LLM répond ==========
        return None