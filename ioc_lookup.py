#!/usr/bin/env python3
"""
ioc_lookup.py - Enriquecimiento de IOCs (IP, URL, hash) con VirusTotal y AbuseIPDB.

Uso:
    python ioc_lookup.py 8.8.8.8
    python ioc_lookup.py https://example.com 44d88612fea8a8f36de82e1278abb02f
    python ioc_lookup.py -f iocs.txt --json > reporte.json

Claves de API (variables de entorno o fichero .env junto al script):
    VT_API_KEY, ABUSEIPDB_API_KEY

Códigos de salida (útiles para pipelines / SOAR):
    0 = todo limpio o sin datos, 1 = sospechoso, 2 = malicioso, 3 = error de uso
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 20

# https://www.abuseipdb.com/categories
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

# Umbrales del veredicto combinado
VT_MALICIOUS_THRESHOLD = 3
ABUSE_MALICIOUS_THRESHOLD = 75
ABUSE_SUSPICIOUS_THRESHOLD = 25

VERDICT_EXIT = {"clean": 0, "unknown": 0, "suspicious": 1, "malicious": 2}


# --------------------------------------------------------------------------- #
# Modelo de datos
# --------------------------------------------------------------------------- #
@dataclass
class Report:
    ioc: str
    type: str
    verdict: str = "unknown"
    country: str | None = None
    reputation: dict = field(default_factory=dict)
    detections: dict = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def load_dotenv(path: Path) -> None:
    """Carga KEY=VALUE de un .env sin sobrescribir variables ya definidas."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def detect_type(ioc: str) -> str:
    """Devuelve 'ip', 'hash', 'url' o lanza ValueError."""
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]+", ioc) and len(ioc) in HASH_LENGTHS:
        return "hash"
    if re.match(r"^[a-z][a-z0-9+.-]*://", ioc, re.I):
        return "url"
    # Dominio / host sin esquema -> lo tratamos como URL
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/\S*)?", ioc, re.I):
        return "url"
    raise ValueError(f"No se reconoce el tipo de IOC: {ioc!r}")


def refang(ioc: str) -> str:
    """Convierte IOCs 'defanged' (hxxp, [.], (.)) a su forma real."""
    ioc = ioc.strip()
    ioc = re.sub(r"^hxxp", "http", ioc, flags=re.I)
    return ioc.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def http_get(url: str, headers: dict, params: dict | None = None) -> dict:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def describe_http_error(source: str, exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        reasons = {401: "API key inválida", 403: "acceso denegado",
                   429: "límite de peticiones alcanzado (rate limit)"}
        return f"{source}: HTTP {exc.code} - {reasons.get(exc.code, exc.reason)}"
    if isinstance(exc, urllib.error.URLError):
        return f"{source}: error de red - {exc.reason}"
    return f"{source}: {exc}"


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
def vt_endpoint(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"{VT_BASE}/ip_addresses/{ioc}"
    if ioc_type == "hash":
        return f"{VT_BASE}/files/{ioc}"
    url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
    return f"{VT_BASE}/urls/{url_id}"


def query_virustotal(report: Report, api_key: str) -> None:
    try:
        data = http_get(vt_endpoint(report.ioc, report.type), {"x-apikey": api_key})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            report.sources["virustotal"] = {"found": False}
            return
        report.errors.append(describe_http_error("VirusTotal", exc))
        return
    except Exception as exc:  # noqa: BLE001 - cualquier fallo de red no debe abortar el lote
        report.errors.append(describe_http_error("VirusTotal", exc))
        return

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())

    report.detections = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "ratio": f"{stats.get('malicious', 0)}/{total}",
    }
    report.reputation["virustotal"] = attrs.get("reputation")

    if report.type == "ip":
        report.country = report.country or attrs.get("country")
        report.details.update({"as_owner": attrs.get("as_owner"), "asn": attrs.get("asn"),
                               "network": attrs.get("network")})
    elif report.type == "url":
        report.categories.extend(sorted(set(attrs.get("categories", {}).values())))
        report.details.update({"final_url": attrs.get("last_final_url"),
                               "title": attrs.get("title")})
    elif report.type == "hash":
        threat = attrs.get("popular_threat_classification", {})
        if threat.get("suggested_threat_label"):
            report.categories.append(threat["suggested_threat_label"])
        report.categories.extend(c.get("value") for c in threat.get("popular_threat_category", []))
        report.details.update({"file_type": attrs.get("type_description"),
                               "name": attrs.get("meaningful_name"),
                               "size": attrs.get("size"), "sha256": attrs.get("sha256")})

    report.sources["virustotal"] = {
        "found": True,
        "link": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(report.ioc, safe='')}",
    }


# --------------------------------------------------------------------------- #
# AbuseIPDB
# --------------------------------------------------------------------------- #
def query_abuseipdb(report: Report, ip: str, api_key: str) -> None:
    try:
        data = http_get(f"{ABUSE_BASE}/check", {"Key": api_key},
                        {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})["data"]
    except Exception as exc:  # noqa: BLE001
        report.errors.append(describe_http_error("AbuseIPDB", exc))
        return

    report.reputation["abuseipdb_score"] = data.get("abuseConfidenceScore")
    report.country = data.get("countryCode") or report.country

    cat_ids = {c for r in data.get("reports") or [] for c in r.get("categories", [])}
    report.categories.extend(ABUSE_CATEGORIES.get(c, f"Cat-{c}") for c in sorted(cat_ids))

    report.details.update({
        "resolved_ip": ip if ip != report.ioc else None,
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
        "is_tor": data.get("isTor"),
        "is_whitelisted": data.get("isWhitelisted"),
        "total_reports": data.get("totalReports"),
        "last_reported": data.get("lastReportedAt"),
    })
    report.sources["abuseipdb"] = {"found": True, "link": f"https://www.abuseipdb.com/check/{ip}"}


def resolve_host(url: str) -> str | None:
    host = urllib.parse.urlsplit(url if "://" in url else f"http://{url}").hostname
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Veredicto
# --------------------------------------------------------------------------- #
def compute_verdict(report: Report) -> str:
    vt_mal = report.detections.get("malicious")
    vt_susp = report.detections.get("suspicious", 0)
    abuse = report.reputation.get("abuseipdb_score")

    if vt_mal is None and abuse is None:
        return "unknown"
    vt_mal = vt_mal or 0
    if vt_mal >= VT_MALICIOUS_THRESHOLD or (abuse or 0) >= ABUSE_MALICIOUS_THRESHOLD:
        return "malicious"
    if vt_mal > 0 or vt_susp > 0 or (abuse or 0) >= ABUSE_SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def analyze(raw_ioc: str, vt_key: str | None, abuse_key: str | None,
            resolve: bool = True) -> Report:
    ioc = refang(raw_ioc)
    try:
        ioc_type = detect_type(ioc)
    except ValueError as exc:
        return Report(ioc=ioc, type="unknown", errors=[str(exc)])

    if ioc_type == "hash":
        ioc = ioc.lower()
    report = Report(ioc=ioc, type=ioc_type)
    if ioc_type == "hash":
        report.details["hash_type"] = HASH_LENGTHS[len(ioc)]

    if vt_key:
        query_virustotal(report, vt_key)
    else:
        report.errors.append("VirusTotal: falta VT_API_KEY")

    # AbuseIPDB solo trabaja con IPs; para URLs resolvemos el host
    ip = ioc if ioc_type == "ip" else (resolve_host(ioc) if ioc_type == "url" and resolve else None)
    if ip:
        if abuse_key:
            query_abuseipdb(report, ip, abuse_key)
        else:
            report.errors.append("AbuseIPDB: falta ABUSEIPDB_API_KEY")

    report.categories = list(dict.fromkeys(c for c in report.categories if c))
    report.details = {k: v for k, v in report.details.items() if v not in (None, "")}
    report.verdict = compute_verdict(report)
    return report


# --------------------------------------------------------------------------- #
# Salida
# --------------------------------------------------------------------------- #
class C:
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, YELLOW, GREEN, GREY, CYAN = "\033[91m", "\033[93m", "\033[92m", "\033[90m", "\033[96m"

    @classmethod
    def disable(cls) -> None:
        for name in ("RESET", "BOLD", "DIM", "RED", "YELLOW", "GREEN", "GREY", "CYAN"):
            setattr(cls, name, "")


VERDICT_STYLE = {
    "malicious": ("MALICIOSO", "RED"), "suspicious": ("SOSPECHOSO", "YELLOW"),
    "clean": ("LIMPIO", "GREEN"), "unknown": ("SIN DATOS", "GREY"),
}


def print_report(r: Report) -> None:
    label, color = VERDICT_STYLE[r.verdict]
    col = getattr(C, color)
    line = "─" * 64
    print(f"{C.CYAN}{line}{C.RESET}")
    print(f"{C.BOLD}IOC:{C.RESET}        {r.ioc}  {C.DIM}({r.type}){C.RESET}")
    print(f"{C.BOLD}Veredicto:{C.RESET}  {col}{C.BOLD}{label}{C.RESET}")
    if r.country:
        print(f"{C.BOLD}País:{C.RESET}       {r.country}")
    if r.detections:
        d = r.detections
        print(f"{C.BOLD}Detecciones:{C.RESET} {col}{d['ratio']}{C.RESET} motores "
              f"{C.DIM}(sospechoso: {d['suspicious']}, inofensivo: {d['harmless']}, "
              f"no detectado: {d['undetected']}){C.RESET}")
    elif r.sources.get("virustotal", {}).get("found") is False:
        print(f"{C.BOLD}Detecciones:{C.RESET} {C.DIM}no encontrado en VirusTotal{C.RESET}")
    rep = []
    if r.reputation.get("virustotal") is not None:
        rep.append(f"VT {r.reputation['virustotal']}")
    if r.reputation.get("abuseipdb_score") is not None:
        rep.append(f"AbuseIPDB {r.reputation['abuseipdb_score']}%")
    if rep:
        print(f"{C.BOLD}Reputación:{C.RESET} {' | '.join(rep)}")
    if r.categories:
        print(f"{C.BOLD}Categoría:{C.RESET}  {', '.join(r.categories)}")
    for key, value in r.details.items():
        print(f"  {C.DIM}{key:<15}{C.RESET} {value}")
    for src in r.sources.values():
        if src.get("link"):
            print(f"  {C.DIM}{'link':<15}{C.RESET} {src['link']}")
    for err in r.errors:
        print(f"  {C.YELLOW}! {err}{C.RESET}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Consulta reputación de IPs, URLs y hashes en VirusTotal y AbuseIPDB.")
    p.add_argument("iocs", nargs="*", help="IP, URL/dominio o hash (MD5/SHA1/SHA256)")
    p.add_argument("-f", "--file", type=Path, help="fichero con un IOC por línea (# = comentario)")
    p.add_argument("-j", "--json", action="store_true", help="salida en JSON")
    p.add_argument("-o", "--output", type=Path, help="guardar el JSON en un fichero")
    p.add_argument("--no-resolve", action="store_true",
                   help="no resolver dominios de URLs para consultarlos en AbuseIPDB")
    p.add_argument("--no-color", action="store_true", help="desactivar colores ANSI")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    load_dotenv(Path(__file__).with_name(".env"))

    iocs = list(args.iocs)
    if args.file:
        iocs += [l.strip() for l in args.file.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.lstrip().startswith("#")]
    if not iocs and not sys.stdin.isatty():
        iocs = [l.strip() for l in sys.stdin if l.strip()]
    if not iocs:
        print("Error: indica al menos un IOC (argumento, -f fichero o stdin).", file=sys.stderr)
        return 3

    vt_key, abuse_key = os.getenv("VT_API_KEY"), os.getenv("ABUSEIPDB_API_KEY")
    if not vt_key and not abuse_key:
        print("Error: define VT_API_KEY y/o ABUSEIPDB_API_KEY (entorno o .env).", file=sys.stderr)
        return 3

    if args.no_color or args.json or not sys.stdout.isatty():
        C.disable()
    elif os.name == "nt":
        os.system("")  # habilita secuencias ANSI en la consola de Windows

    reports = [analyze(i, vt_key, abuse_key, resolve=not args.no_resolve) for i in iocs]

    if args.json or args.output:
        payload = json.dumps([asdict(r) for r in reports] if len(reports) > 1
                             else asdict(reports[0]), indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(payload, encoding="utf-8")
        if args.json:
            print(payload)
    if not args.json:
        for r in reports:
            print_report(r)
        counts = {v: sum(r.verdict == v for r in reports) for v in VERDICT_STYLE}
        print(f"{C.CYAN}{'─' * 64}{C.RESET}")
        print(f"Total: {len(reports)} | " + " | ".join(
            f"{getattr(C, VERDICT_STYLE[v][1])}{VERDICT_STYLE[v][0]}: {n}{C.RESET}"
            for v, n in counts.items() if n))

    return max(VERDICT_EXIT.get(r.verdict, 0) for r in reports)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
