import pytest

from app import app as flask_app
from scanner import scan_website


@pytest.fixture
def client():
    with flask_app.test_client() as test_client:
        yield test_client


def test_navigation_pages_are_available(client):
    for route in ['/', '/history', '/reports', '/settings']:
        response = client.get(route)
        assert response.status_code == 200


def test_scan_detects_https_and_security_headers():
    report = scan_website('https://example.com')

    assert isinstance(report['score'], int)
    assert 1 <= report['score'] <= 10
    assert report['risk_level'] in {'Low', 'Moderate', 'High', 'Critical'}
    assert 'summary' in report
    assert 'checks' in report


def test_scan_detects_missing_security_headers(monkeypatch):
    class DummyResponse:
        status_code = 200
        headers = {
            'Server': 'Apache',
            'X-Powered-By': 'PHP/8.0'
        }

    monkeypatch.setattr('scanner.requests.get', lambda *args, **kwargs: DummyResponse())
    report = scan_website('https://insecure-demo.test')

    security_check = next(check for check in report['checks'] if check['name'] == 'Security headers')
    assert security_check['passed'] is False
    assert report['score'] <= 7


def test_scan_tracks_before_after_vulnerability_counts():
    report = scan_website('https://example.com')

    assert 'vulnerability_trend' in report
    assert report['vulnerability_trend']['before'] >= report['vulnerability_trend']['after']
    assert report['vulnerability_trend']['resolved'] >= 0
    assert 'resolved_issues' in report
    assert len(report['resolved_issues']) == 6
    assert all('severity' in issue and 'resolution' in issue for issue in report['resolved_issues'])


def test_scan_returns_structured_result_for_invalid_url():
    report = scan_website('not-a-url')

    assert report['score'] == 10
    assert report['risk_level'] == 'Critical'
    assert 'Invalid URL' in report['summary']
