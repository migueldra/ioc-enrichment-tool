# IOC Lookup: VirusTotal + AbuseIPDB

Herramienta de línea de comandos para **enriquecer indicadores de compromiso (IOCs)** durante el triaje SOC.
Recibe una IP, URL/dominio o hash, consulta **VirusTotal** y **AbuseIPDB**, y devuelve un resumen con
**veredicto, reputación, país, detecciones y categoría**, en consola o en JSON.

## Características

- Detecta automáticamente el tipo de IOC: IPv4/IPv6, URL/dominio, hash MD5/SHA1/SHA256.
- Acepta IOCs *defanged* (`hxxps://evil[.]com`, `1.2.3[.]4`).
- Para URLs, resuelve el dominio y consulta también la IP en AbuseIPDB.
- Traduce los IDs de categoría de AbuseIPDB (Brute-Force, Port Scan, Phishing...).
- Veredicto combinado: `malicious` / `suspicious` / `clean` / `unknown`.
- Procesa varios IOCs a la vez: argumentos, fichero (`-f`) o `stdin`.
- Código de salida según el peor veredicto (para scripts, SOAR o CI).
- Sin dependencias externas: solo la librería estándar de Python (3.10+).

## Instalación

```bash
git clone <repo> && cd <repo>
cp .env.example .env      # y rellena tus claves
```

Claves gratuitas: [VirusTotal](https://www.virustotal.com/gui/my-apikey) · [AbuseIPDB](https://www.abuseipdb.com/account/api).
También pueden definirse como variables de entorno `VT_API_KEY` y `ABUSEIPDB_API_KEY`.

## Uso

```bash
python ioc_lookup.py 185.220.101.1
python ioc_lookup.py hxxps://suspicious-site[.]com/login
python ioc_lookup.py 44d88612fea8a8f36de82e1278abb02f --json
python ioc_lookup.py -f iocs.txt -o reporte.json
cat iocs.txt | python ioc_lookup.py --json
```

| Opción | Descripción |
|---|---|
| `-f, --file` | Fichero con un IOC por línea (`#` para comentarios) |
| `-j, --json` | Salida en JSON por stdout |
| `-o, --output` | Guarda el JSON en un fichero |
| `--no-resolve` | No resolver dominios para AbuseIPDB |
| `--no-color` | Desactiva colores ANSI |

### Ejemplo de salida

```
────────────────────────────────────────────────────────────────
IOC:        185.220.101.1  (ip)
Veredicto:  MALICIOSO
País:       RU
Detecciones: 12/83 motores (sospechoso: 1, inofensivo: 50, no detectado: 20)
Reputación: VT -45 | AbuseIPDB 100%
Categoría:  Port Scan, Brute-Force, SSH
  as_owner        Evil Hosting
  usage_type      Data Center/Web Hosting/Transit
  total_reports   321
  link            https://www.abuseipdb.com/check/185.220.101.1
────────────────────────────────────────────────────────────────
Total: 1 | MALICIOSO: 1
```

## Lógica del veredicto

| Veredicto | Condición |
|---|---|
| `malicious` | ≥ 3 motores de VT lo marcan como malicioso **o** AbuseIPDB score ≥ 75 |
| `suspicious` | ≥ 1 detección (maliciosa o sospechosa) en VT **o** AbuseIPDB score ≥ 25 |
| `clean` | Hay datos y ninguna condición anterior se cumple |
| `unknown` | Ninguna fuente tiene información |

Los umbrales son constantes al inicio del script y se pueden ajustar.

## Códigos de salida

`0` limpio/sin datos · `1` sospechoso · `2` malicioso · `3` error de uso

```bash
python ioc_lookup.py "$IP" --json > /dev/null || echo "IOC con reputación negativa"
```

## Tests

```bash
python -m unittest -v
```

Los tests simulan las APIs, así que no consumen cuota ni necesitan claves.

## Límites

- La API pública de VirusTotal permite 4 peticiones/minuto y 500/día. Si se supera, el script muestra el error `429` y continúa con el resto de IOCs.
- AbuseIPDB solo evalúa IPs; los hashes se consultan únicamente en VirusTotal.
