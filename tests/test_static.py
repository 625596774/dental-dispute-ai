import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StaticSiteTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_no_external_scripts_or_file_upload(self):
        html = self.read("site/index.html")
        self.assertIsNone(re.search(r'<script[^>]+https?://', html, re.I))
        self.assertIsNone(re.search(r'type=["\']file["\']', html, re.I))

    def test_safe_text_rendering(self):
        app = self.read("site/app.js")
        self.assertNotRegex(app, r"\.innerHTML\s*=")
        self.assertIn("textContent = text", app)

    def test_api_privacy_timeout_and_fallbacks(self):
        app = self.read("site/app.js")
        for expected in ("store: false", "AbortController", "config.timeoutMs", "body.reasoning =", "body.reasoning_effort ="):
            self.assertIn(expected, app)

    def test_local_storage_uses_ciphertext_envelope(self):
        app = self.read("site/app.js")
        self.assertIn('name: "AES-GCM"', app)
        self.assertIn("ciphertext: bytesToBase64", app)
        self.assertNotRegex(app, r"localStorage\.setItem\([^,]+,\s*secrets\.apiKey")
        self.assertNotRegex(app, r"sessionStorage|indexedDB|document\.cookie")

    def test_risk_rules_and_no_fake_handoff(self):
        app = self.read("site/app.js")
        self.assertIn("呼吸困难", app)
        self.assertIn("篡改病历", app)
        self.assertIn("本平台没有人工律师或人工审核", app)
        self.assertNotRegex(app, r"正在转接律师|已提交人工审核|专家稍后联系|正在通知法律顾问")

    def test_encrypted_config_is_populated(self):
        config = self.read("site/encrypted-config.js")
        self.assertIn('"model": "gpt-5.4"', config)
        for field in ("salt", "iv", "ciphertext"):
            match = re.search(rf'"{field}": "([^"]+)"', config)
            self.assertIsNotNone(match)
            self.assertGreater(len(match.group(1)), 12)
        self.assertNotRegex(config, r"FEIFEIMIAO_API_KEY|SHARED_ACCESS_PASSWORD|Authorization|Bearer\s+\S+")

    def test_legal_sources_are_government_allowlist(self):
        legal = self.read("site/legal-sources.js")
        ids = ("civil_code_1218", "civil_code_1219", "civil_code_1221", "civil_code_1222", "civil_code_1224", "civil_code_1225", "civil_code_1226", "civil_code_1227", "medical_record_copy", "complaint_first_contact", "pip_sensitive_health")
        for source_id in ids:
            self.assertIn(f"{source_id}:", legal)
        urls = re.findall(r'officialUrl: "([^"]+)"', legal)
        self.assertGreaterEqual(len(urls), 12)
        for url in urls:
            self.assertRegex(url, r"^https://[^/]+\.gov\.cn/")

    def test_pages_workflow_publishes_site_only(self):
        workflow = self.read(".github/workflows/deploy-pages.yml")
        for expected in ("path: site", "pages: write", "id-token: write"):
            self.assertIn(expected, workflow)


if __name__ == "__main__":
    unittest.main()
