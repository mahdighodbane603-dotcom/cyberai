# CVE récentes exploitées — Base de connaissances (2025-2026)

## CVE-2026-58644 — Microsoft SharePoint Server désérialisation RCE
- Type : Désérialisation non fiable → RCE
- CVSS : 9.8 (Critique)
- Statut : Exploitée activement (WatchTowr, juillet 2026) — famille CVE-2026-32201, CVE-2026-45659, CVE-2026-56164
- Produits : SharePoint Server sur site non patché
- Détection : versions non patchées, POST anormaux vers /_api/ avec payloads base64
- Remédiation : patch Microsoft du 14/07/2026, limiter l'exposition Internet

## CVE-2026-25089 / CVE-2026-39808 — Fortinet FortiSandbox command injection
- Type : OS Command Injection
- CVSS : 9.8 (Critique)
- Statut : Exploitée activement, catalogue CISA KEV
- Produits : FortiSandbox
- Détection : versions non patchées, trafic anormal vers l'interface d'admin
- Remédiation : correctif Fortinet, ne jamais exposer l'admin à Internet

## CVE-2026-26980 — Ghost CMS SQL injection
- Type : SQL Injection (CWE-89)
- CVSS : 9.4 (Critique)
- Statut : Exploitée activement — campagne ClickFix, 700+ domaines compromis
- Produits : Ghost CMS versions vulnérables
- Détection : version Ghost, redirections malveillantes, scripts injectés
- Remédiation : mise à jour Ghost, scanner les fichiers modifiés

## CVE-2025-61882 — Oracle E-Business Suite RCE
- Type : RCE
- CVSS : 9.8 (Critique)
- Statut : Zero-day exploitée par le groupe Cl0p (exfiltration + extorsion), CISA KEV
- Produits : Oracle EBS 12.2.3 à 12.2.14
- Détection : patches Oracle manquants, trafic anormal sur les services EBS
- Remédiation : correctifs Oracle, priorité haute (ransomware connu)

## CVE-2026-15409 — SonicWall SMA1000 SSRF
- Type : SSRF
- CVSS : 10.0 (Critique)
- Statut : Exploitée activement (CISA KEV)
- Produits : SMA1000, interface Work Place
- Détection : requêtes sortantes anormales depuis l'appliance
- Remédiation : correctif SonicWall, cloisonner l'administration

## CVE-2026-31431 — Linux kernel "Copy Fail" privilege escalation
- Type : LPE locale
- CVSS : 7.8 (Élevée)
- Statut : Divulguée le 29/04/2026, EPSS ~96%
- Produits : noyaux Linux vulnérables
- Détection : uname -a puis comparaison avec les versions patchées, binaires SUID modifiés
- Remédiation : mise à jour du noyau

## CVE-2026-10520 — Ivanti Sentry RCE
- Type : RCE
- CVSS : 10.0 (Critique)
- Statut : Exploitée activement (juin 2026), EPSS ~99%
- Produits : Ivanti Sentry
- Remédiation : correctif Ivanti, limiter l'exposition

## CVE-2026-34197 — Apache ActiveMQ RCE
- Type : RCE
- CVSS : 8.8 (Élevée)
- Statut : Exploitée activement (avril 2026)
- Produits : Apache ActiveMQ
- Remédiation : mise à jour, restreindre l'accès au broker

## CVE-2026-20253 — Splunk Enterprise RCE
- Type : RCE
- CVSS : 9.8 (Critique)
- Statut : Exploitée activement (juin 2026)
- Produits : Splunk Enterprise
- Remédiation : correctif Splunk, vérifier les comptes de service

## CVE-2026-35616 — FortiClient EMS infostealer
- Type : Contrôle d'accès insuffisant (CWE-284)
- CVSS : 9.8 (Critique)
- Statut : Exploitée activement — campagne EKZ infostealer
- Produits : FortiClient EMS
- Remédiation : correctif Fortinet

## CVE-2026-8181 — Burst Statistics (WordPress) auth bypass
- Type : Bypass d'authentification (CWE-287)
- CVSS : 9.8 (Critique)
- Statut : Exploitée activement, 200 000+ sites
- Produits : plugin WordPress Burst Statistics
- Remédiation : mise à jour du plugin

## CVE-2026-45829 — ChromaDB RCE
- Type : RCE
- CVSS : 10.0 (Critique)
- Statut : 73% des instances exposées vulnérables
- Produits : ChromaDB
- Remédiation : mise à jour, ne pas exposer l'API publiquement

## CVE-2025-55182 — Meta React Server Components RCE (React2Shell)
- Type : RCE
- CVSS : 10.0 (Critique)
- Statut : Exploitée massivement (11 familles de ransomware, botnets)
- Produits : apps Next.js / React Server Components
- Remédiation : mettre à jour les dépendances React/Next.js

## CVE-2025-53770 — Microsoft SharePoint désérialisation
- Type : Désérialisation
- CVSS : 9.8 (Critique)
- Statut : Exploitée (6 familles de ransomware)
- Produits : SharePoint Server
- Remédiation : correctifs Microsoft juillet 2025

## CVE-2025-31324 — SAP NetWeaver unrestricted file upload
- Type : Upload non restreint
- CVSS : Critique
- Statut : Exploitée
- Produits : SAP NetWeaver
- Impact : upload de webshell
- Remédiation : correctif SAP

## CVE-2025-25257 — Fortinet FortiWeb SQL injection
- Type : SQL Injection
- CVSS : 9.8 (Critique)
- Statut : Exploitée
- Produits : FortiWeb
- Remédiation : correctif Fortinet

## CVE-2025-0108 — Palo Alto PAN-OS authentication bypass
- Type : Bypass d'authentification
- CVSS : Critique
- Statut : Exploitée activement
- Produits : PAN-OS (interfaces de gestion)
- Remédiation : correctif PAN-OS, restreindre l'accès à la gestion

## CVE-2025-34026 — Versa Concerto authentication bypass
- Type : Bypass d'authentification (CWE-287)
- CVSS : 9.2 (Critique)
- Statut : Exploitée activement (CISA KEV)
- Produits : Versa Concerto 12.1.2 – 12.2.0
- Remédiation : correctif Versa, corriger la config du reverse proxy

## CVE-2026-1731 — BeyondTrust RS/PRA command injection
- Type : OS Command Injection (CWE-78)
- CVSS : Critique
- Statut : Exploitée activement (février 2026)
- Produits : BeyondTrust Remote Support / Privileged Remote Access
- Remédiation : correctif BeyondTrust

## CVE-2026-20127 — Cisco Catalyst SD-WAN
- Type : RCE / injection
- CVSS : Critique
- Statut : Exploitée dans la nature depuis 2023
- Produits : Cisco Catalyst SD-WAN Controller/Manager
- Remédiation : correctifs Cisco