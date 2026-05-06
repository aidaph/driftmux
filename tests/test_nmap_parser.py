from driftmux.parsers.nmap import NmapXmlParser, classify_service
from driftmux.models import OpenPort

XML = """
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Apache httpd" version="2.4.58">
          <cpe>cpe:/a:apache:http_server:2.4.58</cpe>
        </service>
        <script id="http-title" output="Welcome"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.3" />
      </port>
    </ports>
  </host>
</nmaprun>
"""

def test_parse_xml_extracts_services_and_script_findings():
    result = NmapXmlParser.parse(XML, "example.org")
    assert len(result.services) == 2
    assert result.services[0].service == "http"
    assert "apache-httpd" in result.services[0].classifications
    assert len(result.findings) == 1
    assert result.findings[0].scanner == "nmap"


def test_classify_service_detects_kubernetes_and_http():
    svc = OpenPort(port=6443, protocol="tcp", state="open", service="https", product="kube-apiserver", version="1.29")
    labels = classify_service(svc)
    assert "http" in labels
    assert "kubernetes" in labels
