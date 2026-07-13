from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from penpal.nmap_parser import NmapParseError, parse_nmap_xml, parse_nmap_xml_text


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

    def test_rejects_xml_entities_from_files_and_inline_input(self) -> None:
        malicious = '<!DOCTYPE nmaprun [<!ENTITY payload "boom">]><nmaprun>&payload;</nmaprun>'
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "scan.xml"
            path.write_text(malicious, encoding="utf-8")
            utf16_path = Path(temp_dir) / "scan-utf16.xml"
            utf16_path.write_bytes(malicious.encode("utf-16"))

            with self.assertRaisesRegex(NmapParseError, "declarations are not allowed"):
                parse_nmap_xml(path)
            with self.assertRaisesRegex(NmapParseError, "declarations are not allowed"):
                parse_nmap_xml(utf16_path)
            with self.assertRaisesRegex(NmapParseError, "declarations are not allowed"):
                parse_nmap_xml_text(malicious)

    def test_rejects_oversized_xml_before_parsing(self) -> None:
        with patch("penpal.nmap_parser.MAX_NMAP_XML_BYTES", 4):
            with self.assertRaisesRegex(NmapParseError, "exceeds 4 bytes"):
                parse_nmap_xml_text("<nmaprun/>")

            with TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "large.xml"
                path.write_bytes(b"<nmaprun/>")
                with self.assertRaisesRegex(NmapParseError, "exceeds 4 bytes"):
                    parse_nmap_xml(path)


if __name__ == "__main__":
    unittest.main()
