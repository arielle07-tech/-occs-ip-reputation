# Analyseur de reputation IP

Application web (FastAPI) pour analyser la reputation de plusieurs adresses IP
simultanement via AbuseIPDB et VirusTotal, avec export du resultat en rapport PDF.

## Fonctionnalites

- Saisie de plusieurs IP (une par ligne, ou separees par virgules/espaces), IPv4 et IPv6
- Interrogation en parallele d'AbuseIPDB et VirusTotal
- Score combine pondere (60% AbuseIPDB / 40% VirusTotal) et verdict SAIN / SUSPECT / MALVEILLANT
- Detection des categories de menace (spam, phishing, botnet, brute-force, etc.)
- Export d'un rapport PDF (synthese + fiche detaillee par IP)
- Aucune persistance en base : chaque analyse est independante, le PDF est le seul livrable conserve

## Installation

```bash
cd ip-reputation-app
python -m venv venv
source venv/bin/activate   # Windows : venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration des cles API

1. Copier `.env.example` en `.env`
2. Renseigner tes cles :
   - `ABUSEIPDB_API_KEY` : https://www.abuseipdb.com/account/api (compte gratuit suffisant pour des tests)
   - `VIRUSTOTAL_API_KEY` : https://www.virustotal.com/gui/my-apikey

```bash
cp .env.example .env
# puis editer .env avec tes cles
```

## Lancement

```bash
uvicorn app.main:app --reload --port 8000
```

Ouvrir ensuite http://127.0.0.1:8000 dans le navigateur.

## Structure du projet

```
ip-reputation-app/
├── app/
│   ├── main.py         # Routes FastAPI (/api/analyze, /api/report, /api/health)
│   ├── reputation.py   # Appels AbuseIPDB / VirusTotal + calcul du score
│   └── report.py       # Generation du rapport PDF (reportlab)
├── static/
│   └── index.html      # Interface (une seule page, JS natif)
├── requirements.txt
├── .env.example
└── README.md
```

## Notes

- Limite : 50 adresses IP par analyse (protection contre le rate-limiting des APIs
  gratuites — AbuseIPDB : 1000 requetes/jour en gratuit, VirusTotal : 4 requetes/min).
- Si une des deux cles API n'est pas configuree, l'appli continue de fonctionner en
  se basant uniquement sur la source disponible (l'indicateur en haut de page te le signale).
- Les seuils de verdict (SAIN < 30 <= SUSPECT < 75 <= MALVEILLANT) et la ponderation
  60/40 sont definis en haut de `app/reputation.py` — modifiables facilement.
- Pour un futur deploiement : ajouter une authentification (l'appli n'en a aucune
  actuellement, pensee pour un usage local de test), passer les cles API en secrets
  d'environnement du serveur, et envisager un stockage d'historique si le besoin evolue.
