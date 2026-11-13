from og_patch_resolution import advisory_bug_statement, og_patch_resolution

PIDUSAGE_DESCRIPTION = """### Overview
Affected versions of pidusage pass unsanitized input to `child_process.exec()`, resulting in arbitrary code execution in the `ps` method.

This package is vulnerable to this PoC on Darwin, SunOS, FreeBSD, and AIX.

Windows and Linux are not vulnerable.

### Proof of Concept
```js
var pid = require('pidusage');
```

### Remediation
Update to version 1.1.5 or later.
"""

PIDUSAGE_SUMMARY = (
    "Affected versions of pidusage pass unsanitized input to child_process.exec(), "
    "resulting in arbitrary code execution in the ps method.\n"
    "\n"
    "This package is vulnerable to this PoC on Darwin, SunOS, FreeBSD, and AIX.\n"
    "\n"
    "Windows and Linux are not vulnerable."
)


def test_advisory_bug_statement_keeps_the_overview():
    text = advisory_bug_statement(
        {
            "summary": "PIDUsage Enables OS Command Injection",
            "description": PIDUSAGE_DESCRIPTION,
        }
    )
    assert text == PIDUSAGE_SUMMARY


def test_og_patch_resolution_uses_overview_as_summary(monkeypatch):
    def fake_github_get(url):
        return {
            "ghsa_id": "GHSA-h2p3-h48h-9jj7",
            "cve_id": "CVE-2017-1000220",
            "summary": "PIDUsage Enables OS Command Injection",
            "description": PIDUSAGE_DESCRIPTION,
            "references": ["https://github.com/advisories/GHSA-h2p3-h48h-9jj7"],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "pidusage"},
                    "first_patched_version": "1.1.5",
                }
            ],
        }, None

    monkeypatch.setattr("og_patch_resolution._github_get", fake_github_get)
    result = og_patch_resolution(
        {
            "package_name": "pidusage",
            "current_vulnerabilities": [{"id": "GHSA-h2p3-h48h-9jj7"}],
        }
    )
    assert result["answer_key"]["summary"] == PIDUSAGE_SUMMARY
    assert result["answer_key"]["status"] == "version_only"


def test_og_patch_resolution_uses_osv_when_github_fails(monkeypatch):
    monkeypatch.setattr(
        "og_patch_resolution._github_get",
        lambda url: (None, f"GitHub API 403 for {url}"),
    )
    monkeypatch.setattr(
        "og_patch_resolution._fetch_osv_advisory",
        lambda vuln_id: {
            "ghsa_id": "GHSA-h2p3-h48h-9jj7",
            "cve_id": "CVE-2017-1000220",
            "summary": "PIDUsage Enables OS Command Injection",
            "description": PIDUSAGE_DESCRIPTION,
            "references": [],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "pidusage"},
                    "first_patched_version": "1.1.5",
                }
            ],
        },
    )
    result = og_patch_resolution(
        {
            "package_name": "pidusage",
            "current_vulnerabilities": [{"id": "GHSA-h2p3-h48h-9jj7"}],
        }
    )
    assert result["answer_key"]["status"] == "version_only"
    assert result["answer_key"]["summary"] == PIDUSAGE_SUMMARY
    assert result["answer_key"]["first_patched_version"] == "1.1.5"


def test_og_patch_resolution_unavailable_without_ids():
    result = og_patch_resolution(
        {
            "current_vulnerabilities": [
                {"id": "npm-audit:lodash", "aliases": []}
            ]
        }
    )
    assert result["answer_key"]["status"] == "unavailable"
    assert result["answer_key"]["files"] == []


def test_og_patch_resolution_reads_commit_files(monkeypatch):
    def fake_github_get(url):
        if url.endswith("/advisories/GHSA-35jh-r3h4-6jhm"):
            return {
                "ghsa_id": "GHSA-35jh-r3h4-6jhm",
                "cve_id": "CVE-2020-8203",
                "summary": "Prototype pollution in lodash",
                "references": [
                    "https://github.com/lodash/lodash/commit/abc1234def",
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
                ],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "first_patched_version": {"identifier": "4.17.19"},
                    }
                ],
            }, None
        if "commits/abc1234def" in url:
            return {
                "files": [
                    {
                        "filename": "lodash.js",
                        "patch": "@@ -20,6 +20,8 @@\n     baseRest(function(object, sources) {\n+    if (object.constructor.prototype) {\n+      return object;\n     }\n",
                    },
                    {"filename": "test/test.js"},
                ]
            }, None
        return None, f"unexpected url: {url}"

    monkeypatch.setattr("og_patch_resolution._github_get", fake_github_get)

    result = og_patch_resolution(
        {
            "package_name": "lodash",
            "current_vulnerabilities": [
                {
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "aliases": ["CVE-2020-8203"],
                }
            ],
        }
    )
    answer = result["answer_key"]
    assert answer["status"] == "resolved"
    assert answer["cve_id"] == "CVE-2020-8203"
    assert answer["first_patched_version"] == "4.17.19"
    assert answer["files"] == ["lodash.js", "test/test.js"]
    assert answer["commit_refs"][0]["sha"] == "abc1234def"
    assert "--- a/lodash.js" in (answer["diff"] or "")
    assert "@@ -20,6 +20,8 @@" in (answer["diff"] or "")


def test_user_commit_resolves_an_advisory_that_has_no_commit(monkeypatch):
    def fake_github_get(url):
        if "commits/abc1234" in url:
            return {"files": [{"filename": "quote.js", "patch": "@@ -1 +1 @@\n-old\n+new\n"}]}, None
        return {
            "ghsa_id": "GHSA-test-test-test",
            "summary": "Upgrade only",
            "references": ["https://github.com/advisories/GHSA-test-test-test"],
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "shell-quote"}, "first_patched_version": "1.8.4"}
            ],
        }, None

    monkeypatch.setattr("og_patch_resolution._github_get", fake_github_get)
    result = og_patch_resolution({
        "package_name": "shell-quote",
        "maintainer_commit_url": "https://github.com/ljharb/shell-quote/commit/abc1234",
        "current_vulnerabilities": [{"id": "GHSA-test-test-test"}],
    })
    answer = result["answer_key"]
    assert answer["status"] == "resolved"
    assert answer["first_patched_version"] == "1.8.4"
    assert answer["commit_refs"][0]["sha"] == "abc1234"
    assert answer["files"] == ["quote.js"]
    assert "--- a/quote.js" in (answer["diff"] or "")


def test_og_patch_resolution_version_only_when_no_commit(monkeypatch):
    def fake_github_get(url):
        return {
            "ghsa_id": "GHSA-test-test-test",
            "cve_id": None,
            "summary": "Upgrade only",
            "references": ["https://github.com/advisories/GHSA-test-test-test"],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "demo"},
                    "first_patched_version": {"identifier": "2.0.0"},
                }
            ],
        }, None

    monkeypatch.setattr("og_patch_resolution._github_get", fake_github_get)

    result = og_patch_resolution(
        {
            "package_name": "demo",
            "current_vulnerabilities": [{"id": "GHSA-test-test-test"}],
        }
    )
    assert result["answer_key"]["status"] == "version_only"
    assert result["answer_key"]["first_patched_version"] == "2.0.0"
    assert result["answer_key"]["files"] == []


def test_og_patch_resolution_accepts_string_first_patched_version(monkeypatch):
    def fake_github_get(url):
        return {
            "ghsa_id": "GHSA-35jh-r3h4-6jhm",
            "cve_id": "CVE-2020-8203",
            "summary": "Prototype pollution",
            "references": ["https://github.com/advisories/GHSA-35jh-r3h4-6jhm"],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "first_patched_version": "4.17.19",
                }
            ],
        }, None

    monkeypatch.setattr("og_patch_resolution._github_get", fake_github_get)

    result = og_patch_resolution(
        {
            "package_name": "lodash",
            "current_vulnerabilities": [{"id": "GHSA-35jh-r3h4-6jhm"}],
        }
    )
    assert result["answer_key"]["first_patched_version"] == "4.17.19"
    assert result["answer_key"]["status"] == "version_only"


def test_github_request_uses_verified_ca_bundle_and_token(monkeypatch):
    import ssl
    import og_patch_resolution as module
    monkeypatch.setenv('GITHUB_TOKEN', '  test-token  ')
    seen = []

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return b'{"ghsa_id":"GHSA-example"}'

    def urlopen(request, *, timeout, context):
        seen.append(request)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert len(context.get_ca_certs()) > 0
        assert timeout == module.REQUEST_TIMEOUT_SECONDS
        assert request.get_header('Authorization') == 'Bearer test-token'
        return Response()

    monkeypatch.setattr(module.urllib.request, 'urlopen', urlopen)
    payload, error = module._github_get('https://api.github.com/advisories/GHSA-example')
    assert payload['ghsa_id'] == 'GHSA-example'
    assert error is None
    assert len(seen) == 1


def test_blank_or_missing_token_is_not_sent(monkeypatch):
    import og_patch_resolution as module
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    assert 'Authorization' not in module._github_headers()
    monkeypatch.setenv('GITHUB_TOKEN', '  ')
    assert 'Authorization' not in module._github_headers()


def test_osv_fallback_uses_verified_tls_without_github_token(monkeypatch):
    import ssl
    import og_patch_resolution as module
    monkeypatch.setenv('GITHUB_TOKEN', 'test-token')

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return b'{"id":"GHSA-example","affected":[],"references":[]}'

    def urlopen(request, *, timeout, context):
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert request.get_header('Authorization') is None
        return Response()

    monkeypatch.setattr(module.urllib.request, 'urlopen', urlopen)
    assert module._fetch_osv_advisory('GHSA-example') is not None
