import requests
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin
import re

def can_fetch_robots(url, user_agent='*'):
    try:
        domain = '{uri.scheme}://{uri.netloc}/'.format(uri=requests.utils.urlparse(url))
        rp = RobotFileParser()
        rp.set_url(urljoin(domain, 'robots.txt'))
        rp.read()
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True

def detect_js_redirect(html):
    match = re.search(r'window\.location\.href\s*=\s*["\'](.*?)["\']', html)
    return match.group(1) if match else None

def analyze_malicious_patterns(html):
    patterns = {
        'eval': bool(re.search(r'eval\(', html)),
        'document_write': bool(re.search(r'document\.write\(', html)),
        'base64': bool(re.search(r'base64,', html)),
        'obfuscated': bool(re.search(r'(\\x[0-9a-fA-F]{2}){3,}', html)),
        'iframe': bool(re.search(r'<iframe', html, re.IGNORECASE)),
        'suspicious_script': bool(re.search(r'src=["\'].*\.(php|asp|exe)', html)),
        'javascript_protocol': bool(re.search(r'href=["\']javascript:', html, re.IGNORECASE)),
        'onerror_event': bool(re.search(r'onerror\s*=', html, re.IGNORECASE)),
        'onload_event': bool(re.search(r'onload\s*=', html, re.IGNORECASE)),
        'unescape_function': bool(re.search(r'unescape\(', html)),
        'settimeout': bool(re.search(r'setTimeout\(', html, re.IGNORECASE)),
        'setinterval': bool(re.search(r'setInterval\(', html, re.IGNORECASE)),
        'window_location': bool(re.search(r'window\.location', html)),
        'document_cookie': bool(re.search(r'document\.cookie', html)),
        'eval_atob_btoa': bool(re.search(r'atob\(|btoa\(', html)),
        'script_tag': bool(re.search(r'<script[^>]*>.*?</script>', html, re.DOTALL | re.IGNORECASE)),
        'hidden_elements': bool(re.search(r'style=["\'].*display:\s*none', html, re.IGNORECASE)),
        'html_entity_encoding': bool(re.search(r'&#x?[0-9a-fA-F]+;', html)),
        'iframe_sandbox_bypass': bool(re.search(r'iframe.*sandbox', html, re.IGNORECASE)),
        'form_autosubmit': bool(re.search(r'<form[^>]*onsubmit=', html, re.IGNORECASE)),
        'eval_function_new_function': bool(re.search(r'new Function\(', html)),
        'src_data_uri': bool(re.search(r'src=["\']data:', html, re.IGNORECASE)), 
        'suspicious_css_expression': bool(re.search(r'expression\(', html)),
        'script_src_external': bool(re.search(r'<script[^>]+src=["\']https?://', html, re.IGNORECASE)),
        'iframe_src_external': bool(re.search(r'<iframe[^>]+src=["\']https?://', html, re.IGNORECASE)),
        'eval_script_tag': bool(re.search(r'<script[^>]*>.*eval\(.+?</script>', html, re.DOTALL | re.IGNORECASE))
    }
    return patterns
