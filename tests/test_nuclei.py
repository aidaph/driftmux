from driftmux.scanners.nuclei import NucleiScanner
from driftmux.models import OpenPort


def test_build_target_http_and_https():
    scanner = NucleiScanner()
    svc_http = OpenPort(port=80, protocol="tcp", state="open", service="http")
    svc_https = OpenPort(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")
    assert scanner.scan_many("example.org", svc_http) == "http://example.org:80"
    assert scanner.scan_many("example.org", svc_https) == "https://example.org:443"
