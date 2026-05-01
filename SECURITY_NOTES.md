# Notes de sécurité — Intégration pytr / Trade Republic

Ce document décrit le modèle de menace et les choix de sécurité de l'intégration `pytr` dans `check-trade`.

> **À lire AVANT le premier clic sur "Refresh TR".**

## 1. Architecture en bref

**Aucun identifiant Trade Republic n'est jamais stocké sur disque, nulle part.**

Trade Republic exige un **2FA mobile** : on ne peut pas se logger juste avec phone+PIN, il faut aussi un code envoyé sur l'app mobile. Donc le flow est en 2 étapes :

```
ÉTAPE 1 — initiate                              ÉTAPE 2 — verify
┌──────────────┐                                ┌──────────────┐
│ Modal step 1 │  POST /api/tr/sync/init        │ Modal step 2 │  POST /api/tr/sync/verify
│ phone + PIN  │ ────────────►  ┌─────────┐     │ code         │ ────────────► ┌─────────┐
└──────────────┘                │ Flask   │     └──────────────┘                │ Flask   │
                                │ + pytr  │ ────────► TR push                   │ + pytr  │ → timeline
                                │ in RAM  │     (app mobile)                    │         │ → CSV merge
                                └────┬────┘                                     └────┬────┘
                                     │                                               │
                                     ▼                                               ▼
                            session_id (token urlsafe)                        store.delete()
                            instance pytr in RAM                              api = None
                            TTL 5 min                                         GC Python
```

Cycle de vie des secrets :
| Secret | Existe où | Durée |
|---|---|---|
| Phone + PIN TR | RAM client (champs HTML) puis RAM serveur (TRCredentials) | < 1s, vidés immédiatement après envoi |
| Instance pytr (avec cookie WAF) | RAM serveur (TRSessionStore) | TTL 5 min ou jusqu'à verify |
| session_id | RAM client + RAM serveur | TTL 5 min |
| Code de validation TR | RAM client puis RAM serveur | < 1s |

**Aucune écriture disque** sauf le CSV utilisateur (qui est **chiffré au repos** par le PIN de session check-trade — pas le PIN TR).

## 2. Modèle de menace

### Ce qu'on protège
- Le PIN à 4 chiffres
- Le numéro de téléphone TR
- Le token de session pytr (créé puis détruit dans la même requête)

### Couverture par adversaire

| Adversaire | Couverture |
|---|---|
| Lecture de ton repo Git (push public, partage, fork) | **OK** — aucun cred n'existe sur disque |
| Vol/perte du PC, accès au disque dur | **OK** — aucun cred n'existe sur disque |
| Sync cloud (OneDrive, iCloud) du dossier projet | **OK** — aucun cred n'existe sur disque |
| Backup involontaire (Time Machine, snapshot VM) | **OK** — aucun cred n'existe sur disque |
| Autre user sur la même machine (multi-user) | **OK** au repos. Pendant un sync : possible via dump mémoire (limite Python) |
| Malware avec accès process Python pendant le sync | **Non couvert** (cf. §6) |
| Keylogger sur ta machine | **Non couvert** (cf. §6) |
| MITM sur ton réseau | **Couvert** par TLS de TR (HTTPS forcé par pytr) |
| Quelqu'un qui regarde ton écran pendant la saisie | **Partiellement** (PIN masqué dans le champ password) |
| Stack trace fuitée dans un log/issue/Discord | **OK** — `TRCredentials.__repr__` masque |
| Trade Republic détecte l'API non-officielle | **Non couvert** — risque produit, cf. §3 |

## 3. Risques liés à pytr lui-même

### Risque 1 — API non-officielle = Conditions d'utilisation TR
Trade Republic n'autorise pas explicitement l'accès programmatique. Tu engages **ta responsabilité** :
- Blocage temporaire/définitif du compte (peu documenté mais possible)
- Pas de support TR si quelque chose tourne mal

**Mitigation** : utilisation **strictement en lecture seule**. Le service `tr_sync_service.py` n'expose que `timeline()` et `portfolio()`. Aucun ordre, aucune modification.

### Risque 2 — Déconnexion app mobile
Trade Republic = **une seule session active**. Chaque clic sur "Refresh TR" déconnecte ton téléphone. Ne synchronise pas pendant un trade ouvert.

### Risque 3 — Code tiers
pytr lui-même + ses dépendances (requests, websockets, ecdsa, pygments). Surface d'attaque supply chain :

- Pinne la version : `pip install pytr==X.Y.Z`, puis `pip freeze > requirements.txt`
- Avant un upgrade : lis le CHANGELOG du repo `pytr-org/pytr`
- Lance `pip-audit` régulièrement

### Risque 4 — Comportement réseau de pytr (à vérifier au 1er run)
pytr doit parler **uniquement** à `api.traderepublic.com`. À vérifier :

```powershell
# Windows : dans un terminal pendant que pytr tourne
Get-NetTCPConnection -OwningProcess <PID_python> | Select-Object RemoteAddress, RemotePort
```

```bash
# Linux/Mac
sudo lsof -p <PID_python> -i -n | grep ESTABLISHED
```

**Tu dois ne voir que des IPs résolues vers `*.traderepublic.com`.** Si tu vois un endpoint inconnu (analytics, télémétrie tierce), arrête immédiatement et investigue.

## 4. Risques liés à `check-trade`

### Risque 5 — Le PIN transite par le réseau local
Quand tu cliques "Refresh TR", le PIN voyage du navigateur jusqu'à Flask via HTTP. En dev local (`http://127.0.0.1:5000`), c'est en clair sur l'interface loopback — donc **pas observable depuis l'extérieur**, mais observable par tout process de ta machine qui sniffe la loopback (rare, mais possible).

**Si tu déployais cette app sur un vrai serveur** :
- HTTPS obligatoire (Caddy / nginx en reverse proxy)
- Header `Strict-Transport-Security`
- Idéalement : pas exposé sur internet du tout (réseau privé)

### Risque NEW — Instance pytr en RAM serveur entre les 2 étapes
Pendant la fenêtre [/init → /verify], l'objet `TradeRepublicApi` (qui contient `phone_no`, `pin`, et le cookie WAF) est en RAM serveur dans `TRSessionStore`. Durée : max **5 minutes** (TTL strict, cleanup paresseux à chaque accès + suppression explicite après /verify).

Mitigations en place :
- TTL 5 min strict (`tr_session_store.py:DEFAULT_TTL_SECONDS`)
- `session_id = secrets.token_urlsafe(32)` (256 bits d'entropie — non devinable)
- Bind au `user_id` check-trade : un autre user qui devine le session_id se voit refuser
- Suppression immédiate après /verify, succès **ou échec**
- Erreur "session_id inconnu ou expiré" volontairement vague (pas de leak via timing/messages)

Limites :
- Si Flask crash avec un dump core entre /init et /verify : le PIN est dans le core
- Multi-process WSGI (gunicorn workers > 1) : le store est par-process, donc /verify peut tomber sur un autre worker → "session expirée". Pour ce projet en dev local, c'est un seul process, pas de problème.

### Risque 6 — `app.log` pourrait contenir des fragments
Le code prend deux précautions :
- `TRCredentials.__repr__` retourne `TRCredentials(phone=+336***78, pin=****)`
- Toutes les exceptions levées par `tr_sync_service` utilisent `from None` pour casser la chaîne d'exception (pour qu'un `traceback` ne ré-affiche pas l'exception originale qui pourrait contenir le PIN dans une frame)

**À toi de vérifier** régulièrement :
```bash
grep -E "phone|pin" app.log
```
Tu ne dois **JAMAIS** voir un PIN en clair ou un numéro complet. Si tu en vois un, c'est un bug — corrige immédiatement.

`app.log` est dans `.gitignore`.

### Risque 7 — Cache pytr local
Selon les versions, pytr peut créer un cache de session dans `~/.pytr/`. Ce cache contient un token qui équivaut à une auth.

**Recommandation** : après chaque session de dev, nettoie :
```powershell
Remove-Item -Recurse -Force "$env:USERPROFILE\.pytr" -ErrorAction SilentlyContinue
```

`.pytr/` est dans `.gitignore`.

### Risque 8 — Le navigateur pourrait offrir d'enregistrer le mot de passe
Atténué par :
- `autocomplete="new-password"` sur le champ PIN
- `autocomplete="off"` sur le formulaire entier
- Les champs sont vidés en JS dès l'envoi et à l'ouverture/fermeture de la modal

**Mais** Chrome/Firefox/Safari ignorent parfois `autocomplete="off"` pour les champs `password`. Si ton navigateur te propose d'enregistrer le PIN : **refuse**.

## 5. Checklist avant le premier vrai test

**Setup une fois :**
- [ ] `pip install pytr playwright` puis `playwright install chromium` (~150 Mo de download)
- [ ] `pip freeze | findstr "pytr playwright" >> requirements.txt`

**Avant chaque sync :**
- [ ] App TR mobile **OUVERTE** (pour recevoir le push de validation) mais pas en train de trader
- [ ] Tu lances en local uniquement (`http://127.0.0.1:5000`), pas exposé au réseau
- [ ] Tu sais que ça va te déconnecter de l'app TR après le sync

**Vérifications post-1er-run :**
- [ ] `grep -E "pin|phone|countdown" app.log` → ne doit montrer que des masquages (`+33***12, pin=****`) et des durations
- [ ] Vérifier les connexions sortantes au 1er run (§Risque 4)
- [ ] Refuser l'enregistrement du mot de passe si le navigateur le propose
- [ ] Nettoyer `~/.pytr/` si pytr a écrit des cookies (vérifier après le 1er run)

## 6. Limites connues (qu'on n'adresse pas)

- **Python ne zéroise pas la mémoire** : un `del pin` n'efface pas réellement la string de la heap. Un dump mémoire avec accès au process peut exposer le PIN tant qu'il n'a pas été GC.
- **JavaScript non plus** : même limitation côté navigateur. Le PIN tapé peut survivre dans le heap V8 jusqu'au GC.
- **Keylogger** : aucune protection possible côté app si la machine est compromise. C'est ton problème de sécurité OS.
- **Pas de hardware token** : Trade Republic ne supporte pas YubiKey/équivalent — leur app mobile = seul second facteur.
- **pytr n'est pas audité crypto** : on lui fait confiance pour parler proprement à TR.

## 7. Si tu suspectes une fuite

1. **Change ton PIN dans l'app TR mobile** immédiatement
2. Vérifie l'historique des connexions dans l'app TR (Profil → Sécurité → Appareils)
3. Si tu vois une activité non reconnue : contacte TR, ferme les positions ouvertes si nécessaire
4. Supprime `~/.pytr/` au cas où un token y traîne
5. Audit : `grep -E "pin|phone" app.log` puis purge si quelque chose apparaît

## 8. TL;DR

- **Aucun stockage des creds** = **zéro risque de fuite à froid** (le risque principal de l'approche persistée).
- Le risque résiduel est **dynamique** (pendant la requête en RAM) : un attaquant doit déjà avoir compromis ta machine pour exploiter ça.
- Le **vrai risque produit** reste TR qui peut bloquer ton compte. Garde le parser PDF comme méthode de secours.
