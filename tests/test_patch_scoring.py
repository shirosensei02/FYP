from patch_scoring import patch_scoring


VENDOR_ESCAPE_DIFF = """\
--- a/src/index.js
+++ b/src/index.js
@@ -10,6 +10,7 @@ function render(input) {
   const value = input || "";
+  const safe = escape(value);
   return safe;
 }
"""

GENERATED_ESCAPE_DIFF = """\
--- a/src/index.js
+++ b/src/index.js
@@ -10,6 +10,7 @@ function render(input) {
   const value = input || "";
+  const safe = escape(value);
   return safe;
 }
"""

GENERATED_TYPEOF_DIFF = """\
--- a/src/index.js
+++ b/src/index.js
@@ -80,4 +80,6 @@ function unused(input) {
+  if (typeof input !== "string") {
+    return "";
+  }
   return input;
 }
"""

GENERATED_VERSION_DIFF = """\
--- a/package.json
+++ b/package.json
@@ -1,6 +1,6 @@
 {
   "name": "demo",
-  "version": "1.0.0"
+  "version": "1.0.1"
 }
"""


def test_patch_scoring_skips_without_vendor_files():
    result = patch_scoring(
        {
            "current_patch": {"diff": "--- a/index.js\n+++ b/index.js\n", "target_files": ["index.js"]},
            "answer_key": {"status": "unavailable", "files": []},
        }
    )
    score = result["patch_score"]
    assert score["status"] == "skipped"
    assert score["location"] == "skipped"
    assert score["strategy"] == "skipped"
    assert score["completeness"] == "skipped"
    assert score["location_score"] is None
    assert score["strategy_score"] is None


def test_patch_scoring_location_overlap_from_unified_diff():
    result = patch_scoring(
        {
            "current_patch": {
                "diff": (
                    "--- a/src/index.js\n"
                    "+++ b/src/index.js\n"
                    "@@\n"
                    "--- a/README.md\n"
                    "+++ b/README.md\n"
                )
            },
            "answer_key": {"status": "resolved", "files": ["src/index.js", "lib/util.js"]},
        }
    )
    score = result["patch_score"]
    assert score["status"] == "scored"
    assert score["location"] == "overlapping"
    assert score["matched_files"] == ["src/index.js"]
    assert score["missing_files"] == ["lib/util.js"]
    assert score["extra_files"] == ["readme.md"]
    assert score["location_score"] == 0.3333
    assert score["location_file_jaccard"] == 0.3333


def test_patch_scoring_same_location_and_strategy():
    result = patch_scoring(
        {
            "current_patch": {"diff": GENERATED_ESCAPE_DIFF},
            "answer_key": {
                "status": "resolved",
                "files": ["src/index.js"],
                "diff": VENDOR_ESCAPE_DIFF,
            },
        }
    )
    score = result["patch_score"]
    assert score["location"] == "same"
    assert score["location_overlap"] == 1.0
    assert score["matched_hunks"] == 1
    assert score["strategy"] == "same"
    assert score["strategy_generated"] == "sanitization"
    assert score["strategy_vendor"] == "sanitization"
    assert score["strategy_score"] == 1.0
    assert score["completeness"] == "full"
    assert score["completeness_score"] == 1.0


def test_patch_scoring_similar_strategy_partial_completeness():
    result = patch_scoring(
        {
            "current_patch": {"diff": GENERATED_TYPEOF_DIFF},
            "answer_key": {
                "status": "resolved",
                "files": ["src/index.js", "lib/util.js"],
                "diff": VENDOR_ESCAPE_DIFF,
            },
            "validation": {"revalidation_scan_clean": False},
            "remaining_vulnerabilities": [{"id": "GHSA-test"}],
        }
    )
    score = result["patch_score"]
    assert score["location"] == "overlapping"
    assert score["strategy"] == "similar"
    assert score["strategy_generated"] == "validation"
    assert score["strategy_vendor"] == "sanitization"
    assert score["completeness"] == "partial"


def test_patch_scoring_different_strategy_none_completeness():
    result = patch_scoring(
        {
            "current_patch": {"diff": GENERATED_VERSION_DIFF},
            "answer_key": {
                "status": "resolved",
                "files": ["src/index.js"],
                "diff": VENDOR_ESCAPE_DIFF,
            },
            "validation": {"revalidation_scan_clean": False},
            "remaining_vulnerabilities": [{"id": "GHSA-test"}],
        }
    )
    score = result["patch_score"]
    assert score["location"] == "different"
    assert score["strategy"] == "different"
    assert score["strategy_generated"] == "version_bump"
    assert score["completeness"] == "none"


def test_patch_scoring_scan_clean_counts_as_complete():
    result = patch_scoring(
        {
            "current_patch": {"diff": GENERATED_TYPEOF_DIFF},
            "answer_key": {
                "status": "resolved",
                "files": ["src/index.js"],
                "diff": VENDOR_ESCAPE_DIFF,
            },
            "validation": {"revalidation_scan_clean": True},
        }
    )
    assert result["patch_score"]["completeness"] == "full"


def test_patch_scoring_version_only_uses_bump_as_vendor_strategy():
    result = patch_scoring(
        {
            "current_patch": {"diff": GENERATED_VERSION_DIFF},
            "answer_key": {
                "status": "version_only",
                "files": [],
                "diff": None,
                "first_patched_version": "1.0.1",
            },
            "validation": {"revalidation_scan_clean": True},
        }
    )
    score = result["patch_score"]
    assert score["location"] == "skipped"
    assert score["strategy"] == "same"
    assert score["strategy_vendor"] == "version_bump"
    assert score["completeness"] == "full"


def test_patch_scoring_patches_mongo_when_mongo_id_present(monkeypatch):
    seen: dict = {}

    def fake_persist(mongo_id, score, answer_key):
        seen["mongo_id"] = mongo_id
        seen["patch_score"] = score
        seen["answer_key"] = answer_key

    monkeypatch.setattr("patch_scoring._persist_score", fake_persist)
    result = patch_scoring(
        {
            "mongo_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "current_patch": {"diff": GENERATED_ESCAPE_DIFF},
            "answer_key": {
                "status": "resolved",
                "files": ["src/index.js"],
                "diff": VENDOR_ESCAPE_DIFF,
            },
        }
    )
    assert seen["mongo_id"] == "aaaaaaaaaaaaaaaaaaaaaaaa"
    assert seen["patch_score"] == result["patch_score"]
    assert seen["answer_key"]["status"] == "resolved"
