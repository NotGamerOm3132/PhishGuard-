import urllib.parse, re
from collections import Counter

# Basic local blacklist (you can extend this file)
try:
    BLACKLIST = set(open('blacklist.txt').read().split())
except Exception:
    BLACKLIST = set(['malicious.com','phishingsite.net','scam.com'])

# Suspicious keywords often used in phishing domains/paths
SUSPICIOUS_KEYWORDS = ['login','secure','account','update','verification','verify','bank','confirm','password','wp-admin']

def domain_entropy(s):
    # approximate entropy over domain characters
    import math
    counts = Counter(s)
    length = len(s)
    if length == 0:
        return 0
    ent = 0.0
    for v in counts.values():
        p = v/length
        ent -= p * (math.log(p,2))
    return ent

def analyze_url(url):
    url = url.strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        # try adding https scheme
        url = 'http://' + url

    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path.lower() if parsed.path else ''
    query = parsed.query.lower() if parsed.query else ''
    score = 100
    reasons = []

    # 1) scheme: http is less secure than https
    if parsed.scheme == 'http':
        score -= 20
        reasons.append('uses_http')

    # 2) blacklist check
    if netloc in BLACKLIST:
        score -= 70
        reasons.append('blacklisted_domain')

    # 3) long domain
    if len(netloc) > 30:
        score -= 10
        reasons.append('very_long_domain')

    # 4) suspicious keyword in domain or path
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in netloc or kw in path or kw in query:
            score -= 10
            reasons.append('suspicious_keyword:'+kw)

    # 5) many hyphens (phishers sometimes use hyphens)
    if netloc.count('-') >= 2:
        score -= 8
        reasons.append('many_hyphens')

    # 6) IP address used instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc) or re.match(r'^\[?[0-9a-f:]+\]?$', netloc):
        score -= 25
        reasons.append('uses_ip_address')

    # 7) entropy check (random looking domains)
    dom_only = netloc.split(':')[0]
    ent = domain_entropy(dom_only.replace('.',''))
    if ent > 3.5:
        score -= 10
        reasons.append('high_entropy_domain')

    # 8) suspicious TLDs (common for cheap phishing sites)
    suspicious_tlds = ['.tk', '.ml', '.cf', '.gq']
    for tld in suspicious_tlds:
        if dom_only.endswith(tld):
            score -= 8
            reasons.append('suspicious_tld:'+tld)

    # Normalize score to 0..100
    score = max(0, min(100, score))

    status = 'safe' if score >= 70 else 'unsafe'

    details = {
        'netloc': netloc,
        'scheme': parsed.scheme,
        'path': path,
        'query': query,
        'score_breakdown_reasons': reasons,
        'entropy': round(ent,2)
    }

    return {'url': url, 'score': score, 'status': status, 'details': details}

def scan_url(url):
    scanner = PhishingScanner()
    return scanner.scan(url)

