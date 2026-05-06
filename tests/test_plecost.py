from unittest.mock import patch, Mock

from driftmux.scanners.plecost import PlecostScanner
from driftmux.models import OpenPort


def test_maybe_wordpress_true_when_service_already_classified():
    scanner = PlecostScanner()
    svc = OpenPort(port=80, protocol="tcp", state="open", service="http", classifications=["wordpress"])
    assert scanner.maybe_wordpress("example.org", svc) is True


@patch("driftmux.scanners.plecost.requests.get")
def test_maybe_wordpress_detects_html_markers(mock_get):
    response = Mock()
    response.text = "<html><a href='/wp-content/plugins/x'></a></html>"
    mock_get.return_value = response
    scanner = PlecostScanner(mode="http")
    assert scanner.maybe_wordpress("example.org") is True
