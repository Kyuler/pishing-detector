# Detector de phishing - Lógica principal

import re
from src.config import TARGET_DOMAINS, SUSPICIOUS_TLDS, PHISHING_KEYWORDS, BLACKLIST, WHITELIST, SAFE_SUFFIXES
from src.utils import (
    similarity, normalize_for_comparison, calculate_entropy, 
    is_ip, count_subdomains, parse_url, get_domain, resolve_ip
)


def check_local_bl(domain):
    """Verifica si el dominio está en blacklist"""
    d = domain.lower()
    return d in BLACKLIST or (d.startswith("www.") and d[4:] in BLACKLIST)


def analyze_url_chars(url):
    """Analiza caracteres sospechosos en la URL"""
    issues = []
    domain = get_domain(url)
    
    if not domain:
        return issues
    
    # Verificaciones básicas
    if "@" in url:
        issues.append("Contiene '@' - redirección oculta")
    
    if "%" in url and re.search(r"%[0-9A-Fa-f]{2}", url):
        issues.append("URL encoding detectado")
    
    if is_ip(domain):
        issues.append("Usa IP en lugar de dominio")
    
    if count_subdomains(domain) > 3:
        issues.append(f"Muchos subdominios ({count_subdomains(domain)})")
    
    if len(domain) > 50:
        issues.append("Dominio muy largo")
    
    if re.search(r"[^\w\-.]", domain):
        issues.append("Caracteres inusuales")
    
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        issues.append("Usa IP directa")
    
    # Verificar TLD sospechoso
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            issues.append(f"TLD sospechoso: {tld}")
            break
    
    # Verificar keywords con dominio conocido
    if domain:
        # Check blacklist primero
        if check_local_bl(domain):
            issues.append("Dominio en blacklist conocido de phishing")
            return issues
        
        # Check whitelist
        if domain in WHITELIST or ("www." + domain) in WHITELIST:
            return issues
        
        parts = domain.split(".")
        main_full = parts[-2] if len(parts) >= 2 else parts[0]
        first_part = main_full.split("-")[0] if "-" in main_full else main_full
        
        all_keywords = PHISHING_KEYWORDS["es"] + PHISHING_KEYWORDS["en"]
        common_services = ["teams", "live", "app", "online", "portal", "official", "secure", "help", "support"]
        all_keywords.extend(common_services)
        
        # Buscar keywords
        found_keywords = [kw for kw in all_keywords if kw in main_full]
        
        # Keywords + dominio similar
        if found_keywords:
            for target in TARGET_DOMAINS:
                t_main = target.split(".")[0]
                sim = similarity(first_part, t_main)
                if sim >= 60 and sim < 100:
                    issues.append(f"Palabra(s) sospechosas: {', '.join(found_keywords[:3])} + dominio similar a {target}")
                    break
        
        # Dominio que empieza con target conocido
        for target in TARGET_DOMAINS:
            t_main = target.split(".")[0]
            if main_full.startswith(t_main) and len(main_full) > len(t_main):
                rest = main_full[len(t_main):]
                if any(rest.startswith(s) for s in SAFE_SUFFIXES):
                    continue
                if rest:
                    issues.append(f"Dominio suplanta a {target}: '{main_full}'")
                    break
        
        # Números en dominio
        if not found_keywords and re.search(r'[0-9]', main_full):
            for target in TARGET_DOMAINS:
                t_main = target.split(".")[0]
                nums_match = re.search(r'[0-9]+', main_full)
                main_norm = main_full.replace(nums_match.group(), '') if nums_match else main_full
                main_norm = normalize_for_comparison(main_norm)
                if similarity(main_norm, t_main) >= 50:
                    issues.append(f"Dominio con números sospechoso: similar a {target}")
                    break
        
        # Alta entropía
        entropy = calculate_entropy(domain)
        unique_ratio = len(set(main_full)) / len(main_full) if main_full else 0
        
        whitelisted = WHITELIST + ["a.com", "a.co", "stackoverflow.com"]
        is_known = domain in TARGET_DOMAINS or "www." + domain in TARGET_DOMAINS or domain in whitelisted
        if not is_known and entropy > 2.5 and unique_ratio > 0.90:
            issues.append(f"Alta entropía - posible dominio aleatorio ({unique_ratio:.0%} caracteres únicos)")
    
    return issues


def analyze_url_path(url):
    """Analiza el path de la URL"""
    issues = []
    parsed = parse_url(url)
    if not parsed:
        return issues
    
    path = parsed.get("path", "")
    query = parsed.get("query", "")
    
    if not path and not query:
        return issues
    
    full_path = path + "?" + query if query else path
    full_path_lower = full_path.lower()
    
    suspicious_words = [
        "login", "signin", "sign-in", "verify", "account", "update", "secure",
        "confirm", "password", "credential", "authenticate", "banking", "invoice",
        "payment", "suspended", "expired", "urgent", "alert", "unusual", "activity",
        "iniciar", "sesion", "verificar", "cuenta", "actualizar", "seguro",
        "contrasena", "acceder", "banco", "pago", "factura", "urgente"
    ]
    
    for word in suspicious_words:
        if word in full_path_lower:
            issues.append(f"Path sospechoso: '{word}' en la ruta")
            break
    
    sensitive_params = ["email", "user", "username", "pass", "password", "token", "code", "auth"]
    for param in sensitive_params:
        if param + "=" in full_path_lower or param + "%3D" in full_path_lower:
            issues.append("Query string con parámetros sensibles")
            break
    
    return issues


def detect_typosquatting(domain):
    """Detecta ataques de typosquatting"""
    if not domain:
        return []
    
    results = []
    d = domain.lower()
    if d.startswith("www."):
        d = d[4:]
    
    if d in TARGET_DOMAINS:
        return []
    
    parts = d.split(".")
    main_domain = parts[-2] if len(parts) >= 2 else parts[0]
    
    has_numbers = bool(re.search(r'[0-9]', main_domain))
    has_dash = '-' in main_domain
    
    for target in TARGET_DOMAINS:
        t = target.lower()
        if t.startswith("www."):
            t = t[4:]
        
        if d == t:
            continue
        
        t_main = t.split(".")[0]
        
        # Comparación directa
        sim = similarity(d, t)
        if sim >= 85 and sim < 100:
            results.append({"target": target, "sim": round(sim, 2), "type": "similitud"})
        
        # Con números/sustitutos
        if has_numbers:
            d_norm = normalize_for_comparison(main_domain)
            t_norm = normalize_for_comparison(t_main)
            sim_norm = similarity(d_norm, t_norm)
            if sim_norm >= 75:
                results.append({"target": target, "sim": round(sim_norm, 2), "type": "números"})
        
        # Con guiones
        if has_dash and "-" in main_domain:
            part_before = main_domain.split("-")[0]
            sim_dash = similarity(part_before, t_main)
            if sim_dash >= 65 and sim_dash < 100:
                results.append({"target": target, "sim": round(sim_dash, 2), "type": "guión"})
    
    # Letras duplicadas
    for target in TARGET_DOMAINS:
        tm = target.split(".")[0]
        dm = main_domain
        if len(dm) > len(tm):
            pattern = re.sub(r'(.)\1+', r'\1', dm)
            if similarity(pattern, tm) >= 80:
                results.append({"target": target, "sim": 85, "type": "duplicado"})
                break
    
    # Typos comunes
    for target in TARGET_DOMAINS:
        tm = target.split(".")[0]
        dm = main_domain
        if dm == tm:
            continue
        sim = similarity(dm, tm)
        diff = abs(len(dm) - len(tm))
        if diff <= 2 and sim >= 65 and sim < 100:
            results.append({"target": target, "sim": round(sim, 2), "type": "typo"})
            break
    
    return results


def calculate_score(url, domain, dns_r, bl_r):
    """Calcula el score de amenaza"""
    score = 0
    reasons = []
    
    url_issues = analyze_url_chars(url)
    path_issues = analyze_url_path(url)
    
    # TLD sospechoso (+3)
    if any("TLD sospechoso" in issue for issue in url_issues):
        score += 3
        reasons.append("TLD sospechoso detectado")
    
    # Keywords + dominio (+3)
    if any("Palabra" in issue or "sospechosa" in issue or "suplanta" in issue for issue in url_issues):
        score += 3
        reasons.append("Palabra sospechosa + dominio conocido")
    
    # Alta entropía (+3)
    if any("entropía" in issue.lower() for issue in url_issues):
        score += 3
        reasons.append("Dominio aleatorio - alta entropía")
    
    # Otros caracteres (+1)
    other = [i for i in url_issues if "TLD" not in i and "Palabra" not in i and "sospechosa" not in i and "entropía" not in i.lower()]
    if other:
        score += 1
    
    # Path sospechoso (+1)
    if path_issues:
        score += 1
        reasons.append("Path de URL sospechoso")
    
    # Typosquatting (+5)
    ts = detect_typosquatting(domain)
    if ts:
        score += 5
        reasons.append(f"Typosquatting: similar a {ts[0]['target']} ({ts[0]['sim']}%)")
    
    # Blacklist (+5)
    if bl_r.get("in_blacklist"):
        score += 5
        reasons.append("Dominio en blacklist")
    
    return score, reasons


def classify(score):
    """Clasifica el resultado"""
    if score <= 2:
        return "SEGURO", "green"
    return "AMENAZA", "red"


def analyze(url):
    """Analiza una URL y retorna el resultado"""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    domain = get_domain(url)
    if not domain:
        return None
    
    dns_r = {"ip": resolve_ip(domain)}
    bl_r = {"in_blacklist": check_local_bl(domain)}
    
    score, reasons = calculate_score(url, domain, dns_r, bl_r)
    level, color = classify(score)
    
    return {
        "url": url,
        "domain": domain,
        "score": score,
        "level": level,
        "reasons": reasons,
        "ip": dns_r.get("ip"),
        "blacklist": bl_r.get("in_blacklist")
    }