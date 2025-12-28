# 🔥 Firestorm

**Web Application Firewall (WAF) Security Testing Tool**

Firestorm to zaawansowane narzędzie do testowania skuteczności Web Application Firewall poprzez wysyłanie setek payloadów ataków różnymi metodami HTTP.

## Funkcje

- **350+ payloadów** w 22 kategoriach ataków (SQLi, XSS, LFI, SSRF, XXE, i więcej)
- **Wiele metod dostarczania** payloadów (GET, POST, JSON body, XML body, Headers, Cookies, Path)
- **Inteligentna klasyfikacja wyników**:
  - 🛡️ **BLOCKED** - WAF zablokował atak (403, 401, 406, 429 lub słowa kluczowe WAF)
  - ⚠️ **PASSED** - Payload przeszedł (status 2xx) - **POTENCJALNA PODATNOŚĆ!**
  - ❌ **ERROR** - Błąd żądania (4xx/5xx) - nie jest podatnością
  - ⏭️ **SKIPPED** - Nie można przetestować (np. wymaga raw socket)
- **Raport CSV** z pełnymi szczegółami każdego testu
- **Payloady 2024/2025** - nowoczesne techniki bypass WAF

## Instalacja

```bash
pip install requests
```

## Użycie

```bash
# Podstawowe użycie
python firestorm.py --host example.com

# Z niestandardowym portem
python firestorm.py --host example.com --port 8080

# Bez generowania CSV
python firestorm.py --host example.com --no-csv
```

## Metody dostarczania payloadów

| Typ payloadu | Metoda HTTP | Gdzie payload |
|--------------|-------------|---------------|
| Standardowe | GET + POST + POST-JSON | Query param, form data, JSON body |
| `header_name` | GET | W nagłówku HTTP |
| `content_type: json` | POST | Body jako application/json |
| `content_type: xml` / kategoria `xxe` | POST | Body jako application/xml |
| `method: path` / kategoria `path_traversal_lfi` | GET | W ścieżce URL |
| `method: cookie` | GET | W nagłówku Cookie |
| `raw_request: true` | - | Pominięte (wymaga socket) |

## Kategorie ataków

### Injection
- **sqli** - SQL Injection (65+ payloadów)
- **nosql_injection** - NoSQL Injection (MongoDB, etc.)
- **cmd_injection** - OS Command Injection
- **ldap_injection** - LDAP Injection
- **ssti** - Server-Side Template Injection

### Cross-Site Scripting
- **xss** - Cross-Site Scripting (55+ payloadów)
- **crlf_injection** - CRLF/Header Injection

### File Inclusion
- **path_traversal_lfi** - Local File Inclusion (45+ payloadów)
- **rfi_ssrf** - Remote File Inclusion / SSRF

### XML/JSON
- **xxe** - XML External Entity (25+ payloadów)
- **xml_body** - XML body attacks
- **json_body** - JSON body attacks
- **graphql_injection** - GraphQL attacks

### Deserialization & Templates
- **deserialization** - Insecure Deserialization
- **prototype_pollution** - JavaScript Prototype Pollution

### Authentication & Authorization
- **jwt_attacks** - JWT Token attacks
- **idor** - Insecure Direct Object Reference
- **cookie_injection** - Cookie-based attacks

### Infrastructure
- **http_smuggling** - HTTP Request Smuggling
- **cors_bypass** - CORS bypass
- **web_cache_poisoning** - Cache Poisoning
- **open_redirect** - Open Redirect

### Modern Attacks (2024/2025)
- **log4j_spring** - Log4j/Spring4Shell
- **headers** - Header-based attacks (50+ payloadów)

## Interpretacja wyników

### Status kody

| Kod | Znaczenie | Klasyfikacja |
|-----|-----------|--------------|
| 200-299 | Sukces | ⚠️ PASSED - potencjalna podatność |
| 300-399 | Redirect | ⚠️ PASSED - może być open redirect |
| 401, 403, 406, 429 | WAF block | 🛡️ BLOCKED |
| 400, 404, 405, etc. | Client error | ❌ ERROR |
| 500-599 | Server error | ❌ ERROR |

### WAF Strength

- **STRONG** (80%+) - WAF blokuje większość ataków
- **MODERATE** (50-79%) - WAF wymaga dostrojenia
- **WEAK** (<50%) - WAF jest nieskuteczny

## Przykładowy output

```
🔥 Firestorm v1.0 - WAF Security Testing Tool
Testing 528 payloads against http://example.com:80/
======================================================================

[*] sqli (60 payloads)
    🛡️ boolean_true                   [GET+POST-form+POS] -> 403 (blocked)
    🛡️ union_select                   [GET+POST-form+POS] -> 403 (blocked)
    ...

======================================================================
OVERALL RESULT
======================================================================
  Total payloads:    528
  Blocked by WAF:    521 (WAF detected attack)
  PASSED (2xx):      0 ⚠️  POTENTIAL VULNERABILITIES!
  Errors (4xx/5xx):  4 (request failed)
  Skipped:           3 (not testable)

  WAF Block Rate:    100.0% (blocked / (blocked + passed))
  WAF Strength:      STRONG
```

## Raport CSV

Automatycznie generowany plik `waf_results_HOST_TIMESTAMP.csv` zawiera:

| Kolumna | Opis |
|---------|------|
| category | Kategoria ataku (sqli, xss, etc.) |
| name | Nazwa payloadu |
| payload_value | Wartość payloadu (skrócona) |
| method | Metoda HTTP użyta do wysłania |
| status | Kod odpowiedzi HTTP |
| result | blocked/passed/error/skipped |
| reason | Powód klasyfikacji |
| response_body | Fragment odpowiedzi serwera |

## Zastrzeżenie

To narzędzie jest przeznaczone **wyłącznie do testowania własnych systemów** lub systemów, na które masz pisemną zgodę. Nieuprawnione testowanie bezpieczeństwa jest nielegalne.

## Licencja

MIT
