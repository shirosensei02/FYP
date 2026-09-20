from bson import ObjectId

import db as db_module


class _UpdateResult:
    def __init__(self, matched_count: int):
        self.matched_count = matched_count
        self.modified_count = matched_count


class _FakeCollection:
    def __init__(self):
        self.calls: list[tuple[dict, dict]] = []

    def update_one(self, filt, update):
        self.calls.append((filt, update))
        return _UpdateResult(1)


def test_update_patch_score_sets_nested_json_on_both_collections(monkeypatch):
    all_col = _FakeCollection()
    pass_col = _FakeCollection()
    monkeypatch.setattr(db_module, "_get_db", lambda: {"all_attempts": all_col, "successful_patches": pass_col})

    mongo_id = str(ObjectId())
    score = {"status": "scored", "location": "overlapping", "strategy": "similar", "completeness": "partial"}
    answer_key = {"status": "resolved", "ghsa_id": "GHSA-test-test-test"}

    assert db_module.update_patch_score(mongo_id, score, answer_key=answer_key) is True

    all_filter, all_update = all_col.calls[0]
    assert all_filter["_id"] == ObjectId(mongo_id)
    assert all_update["$set"]["patch_score"]["location"] == "overlapping"
    assert all_update["$set"]["answer_key"]["ghsa_id"] == "GHSA-test-test-test"

    pass_filter, pass_update = pass_col.calls[0]
    assert pass_filter == {"all_attempts_id": mongo_id}
    assert pass_update["$set"]["patch_score"]["strategy"] == "similar"


def test_update_patch_score_rejects_invalid_id():
    assert db_module.update_patch_score("not-an-objectid", {"location": "same"}) is False
