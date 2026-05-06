from driftmux.models import OpenPort
from driftmux.planner import build_url


def test_build_target_http_and_https():
    svc_http = OpenPort(port=80, protocol="tcp", state="open", service="http")
    svc_https = OpenPort(port=443, protocol="tcp", state="open", service="https", tunnel="ssl")

    assert build_url("example.org", svc_http) == "http://example.org:80"
    assert build_url("example.org", svc_https) == "https://example.org:443"
