from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from penpal.nmap_parser import parse_nmap_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
        <script id="http-title" output="Welcome"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapParserTests(unittest.TestCase):
    def test_parse_open_services(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scan.xml"
            path.write_text(SAMPLE_XML, encoding="utf-8")

            services = parse_nmap_xml(path)

        self.assertEqual([service.port for service in services], [22, 80])
        self.assertEqual(services[0].name, "ssh")
        self.assertEqual(services[1].scripts["http-title"], "Welcome")


if __name__ == "__main__":
    unittest.main()

