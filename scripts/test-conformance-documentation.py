#!/usr/bin/env python3
"""Check visible M1-013 evidence in the working candidate, including new files.

These narrow documentation regressions do not admit format data or prove prose
correct in general. The planning checker, consumer suites and human review own
those boundaries. No Git index or ignored execution report supplies test input.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

import abstract_conformance_registry as registry
from conformance_accounting_reference import predict_corpus


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = "2026-09-02-m1-013-format-v1-registry.json"
ISSUE = "planning/issues/013-abstract-json-conformance-fixtures.md"
DOCUMENTS = {
    "architecture": "docs/ARCHITECTURE.md",
    "threat": "docs/THREAT_MODEL.md",
    "strategy": "docs/TEST_STRATEGY.md",
    "lab": "lab/README.md",
    "roadmap": "docs/ROADMAP.md",
    "adr": "docs/adr/0012-abstract-json-conformance-corpus.md",
    "issue": ISSUE,
    "lessons": "docs/LESSONS_LEARNED.md",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def visible_prose(text):
    # Only the comment/common fence forms used here, not a full Markdown parser.
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return re.sub(r"(?ms)^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1[^\n]*$", "", text)


LESSON_HEADINGS = ("M1-013 local implementation evidence", "M1-013 Task 10 review lessons")


def check_lesson_record(text):
    visible = visible_prose(text)
    required = {"Date", "Context", "Mistaken assumption", "Observed failure",
                "Security or quality impact", "Permanent regression test",
                "New prevention rule", "Documentation or agent-policy updates"}
    for heading in LESSON_HEADINGS:
        match = re.search(r"(?ms)^## " + re.escape(heading) + r"\n(.*?)(?=^## |\Z)", visible)
        require(match is not None, "missing visible lesson record")
        rows = re.findall(r"(?ms)^- \*\*([^*\n]+):\*\*\s*(.*?)(?=^- \*\*|\Z)", match.group(1))
        fields = dict(rows)
        require(len(rows) == len(fields) and set(fields) == required
                and all(value.strip() for value in fields.values())
                and fields.get("Date", "").strip() == "2026-09-03",
                "missing or invalid dated lesson fields")

def check_document(name, text, counts):
    visible = visible_prose(text)
    match = re.search(r"(?ms)^## M1-013 local implementation evidence\n(.*?)(?=^## |\Z)", visible)
    require(match is not None, "missing visible local evidence section")
    section = match.group(1)
    prose = " ".join(section.split())
    require(REGISTRY in section, "missing planning authority reference")
    require(re.search(r"test.only|fixture notation", prose, re.I), "missing test-only boundary")
    require("Task 10 final local verification and freeze" in prose,
            "missing final verification status")
    require(re.search(r"Human line review.{0,80}DCO certification.{0,100}remain pending", prose),
            "missing human review and DCO boundary")
    require(re.search(r"publication.{0,60}(pending|separate)|separate.{0,60}publication", prose, re.I),
            "missing publication boundary")
    require(not re.search(
        r"(?:corpus|fixtures?|JSON|conformance) (?:is |are )?(?:production.ready|authorizes? protected|grants? (?:runtime )?authorization)|"
        r"candidate (?:values?|data) (?:is|are) (?:the )?(?:sole |trusted )?(?:oracle|authority)|"
        r"Task 10 (?:is |now )?(?:complete|passed)|publication (?:is )?authorized",
        " ".join(visible.split()), re.I), "unsupported authority or completion claim")
    required = {
        "architecture": ("bounded_json.py", "abstract_conformance.py", "corpus.json", "independent", "earliest"),
        "threat": ("A1", "A6", "A5", "A8", "diagnostic", "compromised"),
        "strategy": ("predict_corpus", "three", "independent", "charge", "30-second"),
        "lab": ("--self-test", "test-conformance-documentation.py", "synthetic", "compatibility"),
        "roadmap": ("Tasks 2–8", "M2", "M3", "local"),
        "adr": ("013-abstract-json-conformance-fixtures.md", "planning-only", "Tasks 2–8"),
        "issue": ("approved", "Tasks 2–8", "uncommitted", "DCO"),
        "lessons": ("assertion", "scope", "reference", "bounded", "regression"),
    }
    require(all(token in section for token in required[name]), "missing evidence boundary or source")
    if name == "strategy":
        rows = re.findall(r"(?m)^\| ([a-z_]+) \| ([0-9]+) \|$", section)
        actual = {key: int(value) for key, value in rows}
        require(len(rows) == len(actual) and actual == counts, "candidate evidence counts disagree")
    if name == "issue":
        require("proposal pending exact human approval" not in visible,
                "stale issue approval status")
    if name == "adr":
        require("- Status: Accepted" in visible, "accepted ADR status changed")
        require("f3326ab93724b583b72601b4c50627ce624c1120" in visible,
                "accepted decision provenance missing")


class DocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        authority = registry.load_task4_authority()
        snapshots = registry.load_task6_authority()
        # This reference admits actual manifest bytes before reading fixtures.
        # Its independent formulas never import consumer counters.
        _, vectors, total = predict_corpus(authority, snapshots, ROOT)
        manifest = snapshots.manifest
        cls.counts = {
            "snapshots": sum(row[1] == "snapshot" for row in manifest["fixtures"]),
            "histories": sum(row[1] == "history" for row in manifest["fixtures"]),
            "normal_vectors": len(vectors),
            "focused_rows": len(snapshots.focused_rows) + len(authority.histories["focused_expected_tuples"]),
            "focused_invocations": 3 * (len(snapshots.focused_rows) + len(authority.histories["focused_expected_tuples"])),
            "validator_vectors": len(manifest["validator_cases"]),
            "normal_operations": total,
        }

    def candidate(self, name):
        # Deliberately reads working files, including the untracked local issue.
        return (ROOT / DOCUMENTS[name]).read_text(encoding="utf-8")

    def check(self, name, text=None):
        check_document(name, self.candidate(name) if text is None else text, self.counts)

    def test_architecture(self):
        self.check("architecture")

    def test_threat(self):
        self.check("threat")

    def test_strategy(self):
        self.check("strategy")

    def test_semantic_strategy_status_is_current(self):
        text = visible_prose(self.candidate("strategy"))
        self.assertTrue("future executable strategies" not in text,
                        "stale abstract strategy status")

    def test_lab(self):
        self.check("lab")

    def test_roadmap(self):
        self.check("roadmap")

    def test_adr(self):
        self.check("adr")

    def test_issue(self):
        self.check("issue")

    def test_lessons(self):
        self.check("lessons")

    def test_lesson_record_format(self):
        check_lesson_record(self.candidate("lessons"))

    def test_lesson_required_field_removal_rejected(self):
        text = self.candidate("lessons")
        for heading in LESSON_HEADINGS:
            match = re.search(r"(?ms)^## " + re.escape(heading) + r"\n(.*?)(?=^## |\Z)", text)
            self.assertIsNotNone(match, "lesson mutation record missing")
            record = match.group(1)
            fields = re.findall(r"(?m)^- \*\*([^*\n]+):\*\*", record)
            self.assertTrue(len(fields) == 8, "lesson mutation baseline incomplete")
            for field in fields:
                with self.subTest(heading=heading, field=field):
                    changed, edits = re.subn(r"(?ms)^- \*\*" + re.escape(field)
                                            + r":\*\*.*?(?=^- \*\*|\Z)", "", record)
                    self.assertTrue(edits == 1, "lesson field mutation missed target")
                    with self.assertRaisesRegex(AssertionError, "missing or invalid dated lesson fields"):
                        check_lesson_record(text[:match.start(1)] + changed + text[match.end(1):])
            with self.assertRaisesRegex(AssertionError, "missing visible lesson record"):
                check_lesson_record(text[:match.start()] + text[match.end():])

    def test_count_drift_rejected(self):
        text = self.candidate("strategy")
        changed, edits = re.subn(r"(\| normal_operations \| )[0-9]+", r"\g<1>0", text)
        self.assertTrue(edits == 1, "count mutation did not reach evidence")
        with self.assertRaisesRegex(AssertionError, "candidate evidence counts disagree"):
            self.check("strategy", changed)

    def test_hidden_evidence_rejected(self):
        text = self.candidate("lab")
        hidden_forms = ["<!--\n" + text + "\n-->"]
        for indent in range(4):
            for fence in ("```", "~~~"):
                padding = " " * indent
                hidden_forms.append(padding + fence + "markdown\n" + text + "\n" + padding + fence)
        for hidden in hidden_forms:
            with self.assertRaisesRegex(AssertionError, "missing visible local evidence section"):
                self.check("lab", hidden)

    def test_authority_and_completion_overclaims_rejected(self):
        text = self.candidate("issue")
        for claim in ("The corpus authorizes protected sessions.",
                      "Candidate data is the trusted oracle.",
                      "JSON is production-ready.", "Task 10 is complete.",
                      "Publication is authorized."):
            with self.assertRaisesRegex(AssertionError, "unsupported authority or completion claim"):
                self.check("issue", text + "\n" + claim + "\n")

    def test_working_issue_status_rejected_when_stale(self):
        text = self.candidate("issue") + "\nThis local issue is a proposal pending exact human approval.\n"
        with self.assertRaisesRegex(AssertionError, "stale issue approval status"):
            self.check("issue", text)

    def test_missing_final_verification_boundary_rejected(self):
        original = self.candidate("roadmap")
        for token in ("Task 10", "final local", "freeze"):
            with self.subTest(token=token):
                with self.assertRaisesRegex(AssertionError, "missing final verification status"):
                    self.check("roadmap", original.replace(token, "Later work"))
        for token in ("Human line review", "DCO certification", "remain pending"):
            with self.subTest(token=token):
                with self.assertRaisesRegex(AssertionError, "missing human review and DCO boundary"):
                    self.check("roadmap", original.replace(token, "Later work"))


if __name__ == "__main__":
    unittest.main()
