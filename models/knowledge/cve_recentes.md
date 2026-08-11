# CVE récentes exploitées — Base de connaissances (2025-2026)

## CVE-2026-58644 — Microsoft SharePoint Server désérialisation RCE
- **Type :** Désérialisation de données non fiables → RCE
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée activement (WatchTowr, juillet 2026) — série avec CVE-2026-32201, CVE-2026-45659, CVE-2026-56164
- **Produits :** SharePoint Server sur site (versions non patchées)
- **Impact :** Exécution de code à distance sans authentification
- **Détection :** vérifier la version de SharePoint (patch juillet 2026), surveiller les logs IIS pour des requêtes POST anormales vers /_api/ et les payloads base64 encodés
- **Remédiation :** appliquer les correctifs Microsoft du 14 juillet 2026, limiter l'exposition Internet du serveur

## CVE-2026-25089 / CVE-2026-39808 — Fortinet FortiSandbox command injection
- **Type :** OS Command Injection
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée activement, ajoutées au catalogue CISA KEV
- **Produits :** FortiSandbox
- **Impact :** Exécution de commandes arbitraires non authentifiée
- **Détection :** vérifier la version FortiSandbox, surveiller le trafic vers les interfaces d'administration
- **Remédiation :** correctif Fortinet, cloisonner l'admin (ne jamais l'exposer à Internet)

## CVE-2026-26980 — Ghost CMS SQL injection
- **Type :** SQL Injection (CWE-89)
- **CVSS :** 9.4 (Critique)
- **Statut :** Exploitée activement — campagne ClickFix, 700+ domaines compromis
- **Produits :** Ghost CMS (versions vulnérables)
- **Impact :** Compromission de la base de données et du site
- **Détection :** vérifier la version Ghost, rechercher des redirections malveillantes et des scripts injectés
- **Remédiation :** mise à jour Ghost, scanner les fichiers modifiés

## CVE-2025-61882 — Oracle E-Business Suite RCE
- **Type :** RCE
- **CVSS :** 9.8 (Critique)
- **Statut :** Zero-day exploitée activement par le groupe Cl0p (exfiltration + extorsion), catalogue CISA KEV
- **Produits :** Oracle EBS 12.2.3 à 12.2.14
- **Impact :** Compromission totale, vol de données financières
- **Détection :** vérifier les patches Oracle, surveiller le trafic anormal sur les services EBS
- **Remédiation :** correctifs Oracle, priorité haute (ransomware connu)

## CVE-2026-15409 — SonicWall SMA1000 SSRF
- **Type :** Server-Side Request Forgery
- **CVSS :** 10.0 (Critique)
- **Statut :** Exploitée activement (catalogue CISA KEV)
- **Produits :** SMA1000 Appliance, interface Work Place
- **Impact :** Requêtes internes arbitraires, accès aux ressources internes
- **Remédiation :** correctif SonicWall, cloisonnement du réseau d'administration

## CVE-2026-31431 — Linux kernel "Copy Fail" privilege escalation
- **Type :** Élévation de privilèges locale (LPE)
- **CVSS :** 7.8 (Élevée)
- **Statut :** Divulguée publiquement le 29 avril 2026, exploitation en hausse (EPSS ~96%)
- **Produits :** Noyaux Linux vulnérables
- **Impact :** Élévation de privilèges locale vers root
- **Détection :** `uname -a` puis comparaison avec les versions patchées, surveiller les binaires SUID modifiés
- **Remédiation :** mise à jour du noyau

## CVE-2026-10520 — Ivanti Sentry RCE
- **Type :** RCE
- **CVSS :** 10.0 (Critique)
- **Statut :** Exploitée activement (juin 2026), EPSS ~99%
- **Produits :** Ivanti Sentry
- **Impact :** RCE non authentifiée sur l'appliance
- **Remédiation :** correctif Ivanti, limiter l'exposition

## CVE-2026-34197 — Apache ActiveMQ
- **Type :** RCE
- **CVSS :** 8.8 (Élevée)
- **Statut :** Exploitée activement (avril 2026)
- **Produits :** Apache ActiveMQ
- **Impact :** Exécution de code à distance
- **Remédiation :** mise à jour ActiveMQ, restreindre l'accès au broker

## CVE-2026-20253 — Splunk Enterprise RCE
- **Type :** RCE
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée activement (juin 2026)
- **Produits :** Splunk Enterprise
- **Impact :** RCE sur l'instance Splunk
- **Remédiation :** correctif Splunk, vérifier les comptes de service

## CVE-2026-35616 — FortiClient EMS infostealer
- **Type :** Contrôle d'accès insuffisant (CWE-284)
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée activement — campagne EKZ infostealer
- **Produits :** FortiClient EMS
- **Impact :** Accès non autorisé, vol de données
- **Remédiation :** correctif Fortinet

## CVE-2026-8181 — Burst Statistics (WordPress) auth bypass
- **Type :** Bypass d'authentification (CWE-287)
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée activement, 200 000+ sites
- **Produits :** plugin WordPress Burst Statistics
- **Impact :** Contournement d'authentification
- **Remédiation :** mise à jour du plugin

## CVE-2026-45829 — ChromaDB RCE
- **Type :** RCE
- **CVSS :** 10.0 (Critique)
- **Statut :** 73% des instances exposées vulnérables
- **Produits :** ChromaDB
- **Impact :** RCE
- **Remédiation :** mise à jour, ne pas exposer l'API publiquement

## CVE-2025-55182 — Meta React Server Components RCE (React2Shell)
- **Type :** RCE
- **CVSS :** 10.0 (Critique)
- **Statut :** Exploitée massivement (11 familles de ransomware, botnets)
- **Produits :** Applications Next.js / React Server Components
- **Impact :** RCE sur les serveurs applicatifs
- **Remédiation :** mettre à jour les dépendances React/Next.js

## CVE-2025-53770 — Microsoft SharePoint désérialisation
- **Type :** Désérialisation
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée (6 familles de ransomware)
- **Produits :** SharePoint Server
- **Impact :** RCE
- **Remédiation :** correctifs Microsoft juillet 2025

## CVE-2025-31324 — SAP NetWeaver unrestricted file upload
- **Type :** Upload de fichier non restreint
- **CVSS :** Critique
- **Statut :** Exploitée
- **Produits :** SAP NetWeaver
- **Impact :** Upload de webshell, compromission
- **Remédiation :** correctif SAP

## CVE-2025-25257 — Fortinet FortiWeb SQL injection
- **Type :** SQL Injection
- **CVSS :** 9.8 (Critique)
- **Statut :** Exploitée
- **Produits :** FortiWeb
- **Impact :** Accès à la base, contournement WAF
- **Remédiation :** correctif Fortinet

## CVE-2025-0108 — Palo Alto PAN-OS authentication bypass
- **Type :** Bypass d'authentification
- **CVSS :** Critique
- **Statut :** Exploitée activement
- **Produits :** PAN-OS (interfaces de gestion)
- **Impact :** Accès administrateur non authentifié
- **Remédiation :** correctif PAN-OS, restreindre l'accès à la gestion

## CVE-2025-34026 — Versa Concerto authentication bypass
- **Type :** Bypass d'authentification (CWE-287)
- **CVSS :** 9.2 (Critique)
- **Statut :** Exploitée activement (catalogue CISA KEV)
- **Produits :** Versa Concerto 12.1.2 – 12.2.0
- **Impact :** Bypass de l'écran de login (misconfiguration Traefik), accès admin
- **Remédiation :** correctif Versa, corriger la config du reverse proxy

## CVE-2026-1731 — BeyondTrust RS/PRA command injection
- **Type :** OS Command Injection (CWE-78)
- **CVSS :** Critique
- **Statut :** Exploitée activement (février 2026)
- **Produits :** BeyondTrust Remote Support / Privileged Remote Access
- **Impact :** Exécution de commandes à distance
- **Remédiation :** correctif BeyondTrust

## CVE-2026-20127 — Cisco Catalyst SD-WAN
- **Type :** RCE / injection
- **CVSS :** Critique
- **Statut :** Exploitée dans la nature depuis 2023
- **Produits :** Cisco Catalyst SD-WAN Controller/Manager
- **Impact :** Compromission de l'infrastructure SD-WAN
- **Remédiation :** correctifs Cisco