from og_patch_resolution import og_patch_resolution


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
