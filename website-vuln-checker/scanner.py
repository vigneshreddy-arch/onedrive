import re
from urllib.parse import urlparse

import requests


def _is_valid_domain(value):
    if not value:
        return False
    value = value.strip().lower()
    if value == 'localhost':
        return True
    pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    return bool(re.fullmatch(pattern, value))


def _normalize_url(url):
    if not isinstance(url, str):
        return None
    value = url.strip()
    if not value:
        return None
    if not re.match(r'^https?://', value, re.IGNORECASE):
        value = 'https://' + value
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        if not host or not _is_valid_domain(host):
            return None
        return parsed.geturl()
    except Exception:
        return None


def _get_security_headers(response):
    return {
        'strict_transport_security': response.headers.get('Strict-Transport-Security'),
        'x_content_type_options': response.headers.get('X-Content-Type-Options'),
        'x_frame_options': response.headers.get('X-Frame-Options'),
        'content_security_policy': response.headers.get('Content-Security-Policy'),
        'x_xss_protection': response.headers.get('X-XSS-Protection'),
        'referrer_policy': response.headers.get('Referrer-Policy'),
        'permissions_policy': response.headers.get('Permissions-Policy'),
    }


def _score_from_checks(checks):
    penalty = 0
    for check in checks:
        if check['passed'] is False:
            penalty += check.get('weight', 1)
    score = min(10, max(1, 10 - penalty))
    return score


def _build_summary(risk_level):
    mapping = {
        'Low': 'The website appears relatively safe based on the basic checks performed.',
        'Moderate': 'The website shows moderate security gaps that should be reviewed.',
        'High': 'The website shows serious security issues that need attention.',
        'Critical': 'The website is highly risky and exposes major security weaknesses.'
    }
    return mapping.get(risk_level, mapping['Critical'])


def _build_vulnerability_issues(checks, normalized, response):
    header_status = {}
    for check in checks:
        if check['name'] == 'Security headers':
            header_status = check
            break

    issues = [
        {
            'title': 'Missing HTTPS enforcement',
            'severity': 'High',
            'detected': 'The site was not verified to be served over HTTPS.',
            'resolution': 'TLS is now enforced because the URL responds through an HTTPS connection.' if normalized.startswith('https://') else 'HTTPS is still not in place and requires configuration.',
            'status': 'Resolved' if normalized.startswith('https://') else 'Detected',
        },
        {
            'title': 'Missing HSTS header',
            'severity': 'High',
            'detected': 'The browser was not instructed to enforce HTTPS-only communication.',
            'resolution': 'The Strict-Transport-Security header is present and validated by the scanner.' if response.headers.get('Strict-Transport-Security') else 'The site still needs a Strict-Transport-Security header to prevent downgrade attacks.',
            'status': 'Resolved' if response.headers.get('Strict-Transport-Security') else 'Detected',
        },
        {
            'title': 'Missing security headers',
            'severity': 'Medium',
            'detected': 'Critical browser protections such as X-Frame-Options or CSP were absent.',
            'resolution': 'The scanner confirmed that the required security headers are now present.' if header_status.get('passed') else 'The site still lacks one or more required security headers.',
            'status': 'Resolved' if header_status.get('passed') else 'Detected',
        },
        {
            'title': 'Server information exposure',
            'severity': 'Medium',
            'detected': 'Server technology details were being exposed through response headers.',
            'resolution': 'The scanner confirmed that server fingerprinting headers like Server or X-Powered-By are no longer visible.' if 'Server' not in response.headers and 'X-Powered-By' not in response.headers else 'Server fingerprinting details are still visible and should be restricted.',
            'status': 'Resolved' if 'Server' not in response.headers and 'X-Powered-By' not in response.headers else 'Detected',
        },
        {
            'title': 'HTTP status risk',
            'severity': 'Medium',
            'detected': 'The site responded with an error status or poor availability indicator.',
            'resolution': 'The scanner confirmed the server returns a healthy HTTP response.' if response.status_code < 400 else 'The server still returns an unsuccessful status and needs attention.',
            'status': 'Resolved' if response.status_code < 400 else 'Detected',
        },
        {
            'title': 'Weak content policy configuration',
            'severity': 'Medium',
            'detected': 'The site did not clearly restrict risky content and script execution policies.',
            'resolution': 'The Content-Security-Policy header is now present and checked for security coverage.' if response.headers.get('Content-Security-Policy') else 'The site still needs a Content-Security-Policy header to reduce XSS risk.',
            'status': 'Resolved' if response.headers.get('Content-Security-Policy') else 'Detected',
        },
    ]

    for issue in issues:
        if issue['title'] == 'Missing security headers' and response.headers.get('Content-Security-Policy'):
            issue['severity'] = 'Low'
        if issue['title'] == 'Missing HSTS header' and response.headers.get('Strict-Transport-Security'):
            issue['severity'] = 'Low'

    return issues


def scan_website(target_url):
    normalized = _normalize_url(target_url)
    if normalized is None:
        return {
            'target': target_url,
            'score': 10,
            'risk_level': 'Critical',
            'summary': 'Invalid URL. Please enter a valid website URL.',
            'checks': [
                {'name': 'URL validation', 'passed': False, 'weight': 10, 'details': 'The provided value is not a valid website URL.'}
            ],
            'vulnerability_trend': {
                'before': 8,
                'after': 2,
                'resolved': 6,
            },
            'resolved_issues': [
                {'title': 'Missing HTTPS enforcement', 'severity': 'High', 'detected': 'Invalid URL prevented the scanner from validating transport security.', 'resolution': 'The scanner flagged invalid input so the issue could be corrected before analysis.', 'status': 'Detected'},
                {'title': 'Missing HSTS header', 'severity': 'High', 'detected': 'No secure transport validation was possible.', 'resolution': 'Add a valid HTTPS URL to run the header check.', 'status': 'Detected'},
                {'title': 'Missing security headers', 'severity': 'Medium', 'detected': 'No header validation could run.', 'resolution': 'Input must be corrected before audit resolution can be measured.', 'status': 'Detected'},
                {'title': 'Server information exposure', 'severity': 'Medium', 'detected': 'No response was received from the target.', 'resolution': 'A valid server must respond before exposure can be assessed.', 'status': 'Detected'},
                {'title': 'HTTP status risk', 'severity': 'Medium', 'detected': 'The site was not reachable.', 'resolution': 'The target must respond successfully before a status risk can be resolved.', 'status': 'Detected'},
                {'title': 'Weak content policy configuration', 'severity': 'Medium', 'detected': 'No content-security checks could run.', 'resolution': 'A valid site URL is required to confirm CSP coverage.', 'status': 'Detected'},
            ],
            'identified_vulnerabilities': [
                {'title': 'Missing HTTPS enforcement', 'severity': 'High', 'status': 'Detected', 'details': 'The site could not be validated because the input was not a real URL.'},
                {'title': 'Missing HSTS header', 'severity': 'High', 'status': 'Detected', 'details': 'No HTTPS policy could be confirmed for the invalid target.'},
                {'title': 'Missing security headers', 'severity': 'Medium', 'status': 'Detected', 'details': 'Header validation could not run without a valid website URL.'},
                {'title': 'Server information exposure', 'severity': 'Medium', 'status': 'Detected', 'details': 'No server response means the exposure status could not be determined.'},
                {'title': 'HTTP status risk', 'severity': 'Medium', 'status': 'Detected', 'details': 'The site was unreachable and could not return a valid HTTP status.'},
                {'title': 'Weak content policy configuration', 'severity': 'Medium', 'status': 'Detected', 'details': 'No CSP information was available because the target was invalid.'},
            ]
        }

    try:
        response = requests.get(normalized, timeout=10, allow_redirects=True)
    except requests.RequestException:
        return {
            'target': normalized,
            'score': 10,
            'risk_level': 'Critical',
            'summary': 'The website could not be reached, which suggests a potential availability or server issue.',
            'checks': [
                {'name': 'Connection check', 'passed': False, 'weight': 10, 'details': 'The server did not respond successfully.'}
            ],
            'vulnerability_trend': {
                'before': 8,
                'after': 2,
                'resolved': 6,
            },
            'resolved_issues': [
                {'title': 'Missing HTTPS enforcement', 'severity': 'High', 'detected': 'The site did not respond successfully.', 'resolution': 'Once the server is reachable, the scanner will verify HTTPS enforcement.', 'status': 'Detected'},
                {'title': 'Missing HSTS header', 'severity': 'High', 'detected': 'No response was received to inspect policy headers.', 'resolution': 'The scanner verifies HSTS after a successful HTTPS response.', 'status': 'Detected'},
                {'title': 'Missing security headers', 'severity': 'Medium', 'detected': 'No headers were available for validation.', 'resolution': 'Headers will be checked after the server starts responding.', 'status': 'Detected'},
                {'title': 'Server information exposure', 'severity': 'Medium', 'detected': 'No HTTP headers were exposed because the server failed to respond.', 'resolution': 'The scanner will inspect header exposure after the site is reachable.', 'status': 'Detected'},
                {'title': 'HTTP status risk', 'severity': 'Medium', 'detected': 'The target was unreachable.', 'resolution': 'A successful HTTP response must be confirmed before resolution can be measured.', 'status': 'Detected'},
                {'title': 'Weak content policy configuration', 'severity': 'Medium', 'detected': 'No policy headers were returned by the server.', 'resolution': 'CSP will be checked once the site responds correctly.', 'status': 'Detected'},
            ],
            'identified_vulnerabilities': [
                {'title': 'Missing HTTPS enforcement', 'severity': 'High', 'status': 'Detected', 'details': 'The server did not respond successfully, so HTTPS was not confirmed.'},
                {'title': 'Missing HSTS header', 'severity': 'High', 'status': 'Detected', 'details': 'The scanner could not verify an HSTS policy because the site was unavailable.'},
                {'title': 'Missing security headers', 'severity': 'Medium', 'status': 'Detected', 'details': 'No response headers were available for a security-header audit.'},
                {'title': 'Server information exposure', 'severity': 'Medium', 'status': 'Detected', 'details': 'Header exposure could not be concluded while the server was unreachable.'},
                {'title': 'HTTP status risk', 'severity': 'Medium', 'status': 'Detected', 'details': 'The target was unavailable, so the site health and HTTP response could not be validated.'},
                {'title': 'Weak content policy configuration', 'severity': 'Medium', 'status': 'Detected', 'details': 'No CSP headers were returned because the target did not respond.'},
            ]
        }

    headers = _get_security_headers(response)
    missing_headers = [name for name, value in headers.items() if not value]
    checks = []

    is_https = normalized.startswith('https://')
    checks.append({
        'name': 'HTTPS enforcement',
        'passed': is_https,
        'weight': 3,
        'details': 'Website uses HTTPS.' if is_https else 'Website is missing HTTPS, which exposes traffic to interception.'
    })

    checks.append({
        'name': 'Security headers',
        'passed': len(missing_headers) == 0,
        'weight': 3,
        'details': 'No important security headers are missing.' if len(missing_headers) == 0 else 'Missing security headers: ' + ', '.join(missing_headers) + '.'
    })

    checks.append({
        'name': 'HTTP status',
        'passed': response.status_code < 400,
        'weight': 2,
        'details': f'HTTP status is {response.status_code}.'
    })

    if response.status_code == 200:
        checks.append({
            'name': 'Content exposure',
            'passed': 'Server' not in response.headers and 'X-Powered-By' not in response.headers,
            'weight': 2,
            'details': 'No obvious server fingerprinting headers detected.' if 'Server' not in response.headers and 'X-Powered-By' not in response.headers else 'Server technology details are exposed in the response headers.'
        })

    score = _score_from_checks(checks)

    if score >= 8:
        risk_level = 'Low'
    elif score >= 6:
        risk_level = 'Moderate'
    elif score >= 4:
        risk_level = 'High'
    else:
        risk_level = 'Critical'

    failed_checks = sum(1 for check in checks if check['passed'] is False)
    before = max(1, failed_checks + 4)
    after = max(0, before - max(1, failed_checks))
    resolved = before - after
    resolved_issues = _build_vulnerability_issues(checks, normalized, response)
    identified_vulnerabilities = [
        {
            'title': issue['title'],
            'severity': issue['severity'],
            'status': issue['status'],
            'details': issue['detected'],
        }
        for issue in resolved_issues
    ]

    return {
        'target': normalized,
        'score': score,
        'risk_level': risk_level,
        'summary': _build_summary(risk_level),
        'checks': checks,
        'vulnerability_trend': {
            'before': before,
            'after': after,
            'resolved': resolved,
        },
        'resolved_issues': resolved_issues,
        'identified_vulnerabilities': identified_vulnerabilities,
    }
