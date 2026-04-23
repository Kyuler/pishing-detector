# Phishing Detector

from src.detector import analyze, analyze_url_chars, analyze_url_path, detect_typosquatting, classify
from src.utils import get_domain, resolve_ip, check_local_bl
from src.config import TARGET_DOMAINS, SUSPICIOUS_TLDS, PHISHING_KEYWORDS

__version__ = "1.0"
__all__ = ["analyze", "analyze_url_chars", "analyze_url_path", "detect_typosquatting", "classify"]