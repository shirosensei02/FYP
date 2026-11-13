from typing import TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from graph import intake_node
from intake import apply_resume, format_draft, parse_prompt


class _State(TypedDict, total=False):
    user_prompt: str
    package_name: str
    package_version: str
    suspected_issue: str
    maintainer_commit_url: str
    intake_confirmed: bool


PROMPT = (
    "shell-quote@1.8.3 command injection in quote() "
    "https://github.com/ljharb/shell-quote/commit/abc1234 codex"
)


def test_parse_prompt_reads_package_issue_and_commit():
    draft = parse_prompt(PROMPT)
    assert draft["package_name"] == "shell-quote"
    assert draft["package_version"] == "1.8.3"
    assert draft["suspected_issue"] == "command injection in quote()"
    assert draft["maintainer_commit_url"] == "https://github.com/ljharb/shell-quote/commit/abc1234"
    assert draft["model_name"] == "codex"
    assert "suspected issue: \"command injection in quote()\"" in format_draft(draft)
    assert "maintainer patch: https://github.com/ljharb/shell-quote/commit/abc1234" in format_draft(draft)


def test_parse_prompt_with_only_a_package_has_no_issue():
    draft = parse_prompt("lodash@4.17.11")
    assert draft["package_name"] == "lodash"
    assert draft["package_version"] == "4.17.11"
    assert draft["suspected_issue"] == ""
    assert draft["maintainer_commit_url"] == ""
    assert "suspected issue: (none)" in format_draft(draft)
    assert "maintainer patch: (none)" in format_draft(draft)


def test_confirm_accepts_the_draft_and_an_edited_resume_replaces_it():
    draft = parse_prompt(PROMPT)
    accepted = apply_resume(draft, "confirm")
    assert accepted["confirmed"] is True
    assert accepted["draft"]["package_name"] == "shell-quote"

    edited = apply_resume(draft, {
        "confirm": True,
        "package_name": "minimatch",
        "package_version": "3.0.4",
        "suspected_issue": "nested quantifiers",
        "maintainer_commit_url": "",
    })
    assert edited["confirmed"] is True
    assert edited["draft"]["package_name"] == "minimatch"
    assert edited["draft"]["suspected_issue"] == "nested quantifiers"
    assert edited["draft"]["maintainer_commit_url"] == ""

    corrected = apply_resume(draft, "minimatch@3.0.4 still ReDoS")
    assert corrected["confirmed"] is False
    assert corrected["draft"]["package_name"] == "minimatch"
    assert corrected["draft"]["suspected_issue"] == "still ReDoS"
    assert apply_resume(parse_prompt("no package here"), "confirm")["confirmed"] is False


def _intake_app():
    builder = StateGraph(_State)
    builder.add_node("intake_node", intake_node)
    builder.add_edge(START, "intake_node")
    builder.add_edge("intake_node", END)
    return builder.compile(checkpointer=MemorySaver())


def test_intake_waits_for_confirmation_and_applies_an_edit():
    app = _intake_app()
    config = {"configurable": {"thread_id": "intake"}}
    paused = app.invoke({"user_prompt": PROMPT}, config)
    assert paused["__interrupt__"]
    assert "shell-quote@1.8.3" in paused["__interrupt__"][0].value

    resumed = app.invoke(Command(resume={
        "package_name": "shell-quote",
        "package_version": "1.8.3",
        "suspected_issue": "unescaped metacharacters",
        "maintainer_commit_url": "https://github.com/ljharb/shell-quote/commit/abc1234",
    }), config)
    assert resumed["intake_confirmed"] is True
    assert resumed["suspected_issue"] == "unescaped metacharacters"
    assert resumed["package_name"] == "shell-quote"


def test_intake_skips_a_run_that_already_names_the_package():
    app = _intake_app()
    result = app.invoke(
        {"package_name": "lodash", "package_version": "4.17.11"},
        {"configurable": {"thread_id": "direct"}},
    )
    assert result["package_name"] == "lodash"
    assert not result.get("__interrupt__")
    assert not result.get("intake_confirmed")
