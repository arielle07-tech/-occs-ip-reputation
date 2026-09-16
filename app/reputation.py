"""
Logique metier : interrogation des APIs AbuseIPDB + VirusTotal,
calcul d'un score de reputation pondere et extraction des menaces detectees.
"""
import asyncio
import ipaddress
import os
from datetime import datetime, timezone
from typing import Any

import httpx

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Logique "pire des deux sources" : le score combine retenu est le MAX entre
# AbuseIPDB et VirusTotal (et non une moyenne ponderee). Une IP a 100% sur une
# source et 1% sur l'autre doit rester consideree comme MALVEILLANT : un signal
# fort d'une seule source ne doit jamais etre dilue par l'autre.
#
# Verdict binaire : des qu'il existe le moindre signal (au moins un moteur VT
# ou un signalement AbuseIPDB), l'IP est MALVEILLANT. Aucun palier intermediaire
# "SUSPECT" : seul SAIN (aucun signal du tout) fait exception.
THRESHOLD_MALVEILLANT = 75

# Mapping des categories AbuseIPDB (cf. documentation officielle)
ABUSEIPDB_CATEGORIES = {
    1: "Compromission DNS", 2: "Empoisonnement DNS", 3: "Fraude", 4: "Attaque DDoS",
    5: "Brute-force FTP", 6: "Ping of Death", 7: "Phishing", 8: "Fraude VoIP",
    9: "Proxy ouvert", 10: "Spam Web", 11: "Spam Email", 12: "Spam Blog",
    13: "IP VPN", 14: "Scan de ports", 15: "Piratage", 16: "Injection SQL",
    17: "Usurpation (spoofing)", 18: "Brute-force", 19: "Bad Web Bot",
    20: "Hote compromis (botnet)", 21: "Attaque application Web", 22: "SSH",
    23: "IoT cible",
}


def validate_ip(value: str) -> str:
    """Valide et normalise une adresse IP (leve ValueError si invalide)."""
    value = value.strip()
    ipaddress.ip_address(value)  # leve ValueError si invalide (IPv4 ou IPv6)
    return value


async def _query_abuseipdb(client: httpx.AsyncClient, ip: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"available": False, "error": "Cle API AbuseIPDB manquante"}
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 180, "verbose": "true"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"available": False, "error": f"HTTP {resp.status_code} : {resp.text[:200]}"}
        data = resp.json().get("data", {})

        categories_seen: set[int] = set()
        for report in data.get("reports", []) or []:
            for cat in report.get("categories", []) or []:
                categories_seen.add(cat)

        return {
            "available": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "is_whitelisted": data.get("isWhitelisted"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt"),
            "categories": sorted(
                ABUSEIPDB_CATEGORIES.get(c, f"Categorie #{c}") for c in categories_seen
            ),
        }
    except httpx.RequestError as exc:
        return {"available": False, "error": f"Erreur reseau : {exc}"}


async def _query_virustotal(client: httpx.AsyncClient, ip: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"available": False, "error": "Cle API VirusTotal manquante"}
    try:
        resp = await client.get(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=20,
        )
        if resp.status_code != 200:
            return {"available": False, "error": f"HTTP {resp.status_code} : {resp.text[:200]}"}
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) or 1

        # Extraction des verdicts textuels des moteurs qui ont flague l'IP
        threat_labels: set[str] = set()
        results = attrs.get("last_analysis_results", {}) or {}
        for engine_result in results.values():
            if engine_result.get("category") in ("malicious", "suspicious"):
                label = (engine_result.get("result") or "").strip()
                if label and label.lower() not in ("malicious", "malware", "unrated"):
                    threat_labels.add(label)
                elif label:
                    threat_labels.add(label)

        return {
            "available": True,
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country"),
            "network": attrs.get("network"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "threat_labels": sorted(threat_labels)[:15],
        }
    except httpx.RequestError as exc:
        return {"available": False, "error": f"Erreur reseau : {exc}"}


def _compute_verdict(abuse: dict, vt: dict) -> dict[str, Any]:
    abuse_score = abuse.get("abuse_confidence_score", 0) if abuse.get("available") else 0
    vt_score = 0.0
    if vt.get("available") and vt.get("total_engines"):
        vt_score = (vt["malicious_engines"] + 0.5 * vt["suspicious_engines"]) / vt["total_engines"] * 100

    # Score combine = le plus eleve des deux sources disponibles (pas de moyenne).
    scores_disponibles = []
    if abuse.get("available"):
        scores_disponibles.append(abuse_score)
    if vt.get("available"):
        scores_disponibles.append(vt_score)
    combined = max(scores_disponibles) if scores_disponibles else 0.0

    combined = round(combined, 1)

    # Y a-t-il un signal brut, meme faible, sur l'une des deux sources ?
    has_any_signal = (
        (vt.get("available") and (vt.get("malicious_engines", 0) > 0 or vt.get("suspicious_engines", 0) > 0))
        or (abuse.get("available") and abuse.get("abuse_confidence_score", 0) > 0)
    )

    if combined >= THRESHOLD_MALVEILLANT or has_any_signal:
        verdict = "MALVEILLANT"
    else:
        verdict = "SAIN"

    return {"combined_score": combined, "verdict": verdict}


async def analyze_ip(client: httpx.AsyncClient, ip: str, abuse_key: str, vt_key: str) -> dict[str, Any]:
    abuse_result, vt_result = await asyncio.gather(
        _query_abuseipdb(client, ip, abuse_key),
        _query_virustotal(client, ip, vt_key),
    )
    verdict_info = _compute_verdict(abuse_result, vt_result)

    all_categories = list(abuse_result.get("categories", []))
    for label in vt_result.get("threat_labels", []):
        if label not in all_categories:
            all_categories.append(label)

    # Pays : VirusTotal renvoie deja un code pays ISO, AbuseIPDB en repli.
    country = vt_result.get("country") or abuse_result.get("country_code")

    # Fournisseur / AS : uniquement disponible via VirusTotal (network + asn + as_owner).
    # AbuseIPDB ne fournit pas le CIDR/ASN, seulement l'ISP en texte libre (repli).
    network = vt_result.get("network")
    asn = vt_result.get("asn")
    as_owner = vt_result.get("as_owner") or abuse_result.get("isp")

    return {
        "ip": ip,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "abuseipdb": abuse_result,
        "virustotal": vt_result,
        "combined_score": verdict_info["combined_score"],
        "verdict": verdict_info["verdict"],
        "threat_categories": all_categories,
        "country": country,
        "network": network,
        "asn": asn,
        "as_owner": as_owner,
    }


async def analyze_ips(ips: list[str]) -> list[dict[str, Any]]:
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    async with httpx.AsyncClient(trust_env=True) as client:
        tasks = [analyze_ip(client, ip, abuse_key, vt_key) for ip in ips]
        return await asyncio.gather(*tasks)
