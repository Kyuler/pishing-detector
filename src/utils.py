# Utilidades del detector

import re
import math
from collections import Counter


def levenshtein(s1, s2):
    """Calcula distancia de Levenshtein entre dos strings"""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        cur = [i + 1]
        for j, c2 in enumerate(s2):
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (c1 != c2)))
        prev = cur
    return prev[-1]


def similarity(d1, d2):
    """Calcula porcentaje de similitud entre dos dominios"""
    m1 = d1.split(".")[0]
    m2 = d2.split(".")[0]
    dist = levenshtein(m1.lower(), m2.lower())
    maxlen = max(len(m1), len(m2))
    return ((maxlen - dist) / maxlen) * 100 if maxlen > 0 else 0


def normalize_for_comparison(s):
    """Normaliza string: 0->o, 1->l, i->l, l->i"""
    s = s.lower()
    replacements = {'0': 'o', '1': 'l', 'i': 'l', 'l': 'i'}
    return ''.join(replacements.get(c, c) for c in s)


def calculate_entropy(domain):
    """Calcula entropía de Shannon"""
    if not domain:
        return 0
    main = domain.split(".")[0]
    if len(main) < 4:
        return 0
    counts = Counter(main)
    length = len(main)
    entropy = sum(-count/length * math.log2(count/length) for count in counts.values())
    return round(entropy, 2)


def is_ip(domain):
    """Verifica si el dominio es una IP"""
    try:
        import socket
        socket.inet_aton(domain)
        return True
    except:
        return False


def count_subdomains(domain):
    """Cuenta el número de subdominios"""
    parts = domain.split(".")
    return len(parts) - 2 if len(parts) > 2 else 0


def parse_url(url):
    """Parsea una URL"""
    from urllib.parse import urlparse
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        p = urlparse(url)
        return {"scheme": p.scheme, "netloc": p.netloc, "path": p.path, "query": p.query}
    except:
        return None


def get_domain(url):
    """Extrae el dominio de una URL"""
    parsed = parse_url(url)
    if not parsed:
        return None
    netloc = parsed["netloc"]
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return netloc.lower()


def resolve_ip(domain):
    """Resuelve la IP de un dominio"""
    import socket
    try:
        domain = domain.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return socket.gethostbyname(domain)
    except:
        return None