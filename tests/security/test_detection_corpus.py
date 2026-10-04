"""Measure the detector against a labelled corpus instead of asserting examples.

Added by Telegram MCP Enhanced.

Every other detection test pins one hand-picked string, which answers "does this
example still work" and never "what did my rule change break". This module scores
the whole corpus and fails when detection regresses in either direction.

The false-positive rate is the number that decides whether the detector is
usable, and it is the one a rule author is least likely to check: tightening
recall by widening a pattern is easy, and the cost lands on ordinary
conversation where nobody is looking.
"""

from __future__ import annotations

import json

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from mcp_telegram.security.injection import InjectionDetector
from mcp_telegram.security.models import Classification

CORPUS_PATH = Path(__file__).parent / "corpus" / "detection_corpus.json"

MIN_PRECISION = 1.00
MIN_RECALL = 1.00
"""Floors measured against the corpus, excluding documented known limitations.

Both are 1.00 because that is what the detector actually scores on the entries
it is expected to get right — not an aspiration. Any new miss or new false
positive therefore fails the build, which is the entire point of a floor. The
honest headline number, counting the five known limitations as the false
positives they are, is precision 0.93 at recall 1.00; see docs/DETECTION.md.
"""


@dataclass(frozen=True)
class Entry:
    """One labelled example."""

    id: str
    label: Literal["attack", "benign"]
    text: str
    rationale: str
    expect_rules: tuple[str, ...] = ()
    known_limitation: str | None = None


def _load() -> list[Entry]:
    """Validate on load so a malformed entry fails loudly rather than scoring.

    A corpus entry that silently defaults to `benign` would quietly weaken the
    measurement, which is worse than having no measurement at all.
    """
    raw = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise ValueError(f"unsupported corpus schema {raw.get('schema_version')!r}")

    entries: list[Entry] = []
    seen: set[str] = set()
    for item in raw["entries"]:
        missing = {"id", "label", "text", "rationale"} - item.keys()
        if missing:
            raise ValueError(f"corpus entry {item.get('id')!r} lacks {sorted(missing)}")
        if item["label"] not in ("attack", "benign"):
            raise ValueError(f"{item['id']}: unknown label {item['label']!r}")
        if item["id"] in seen:
            raise ValueError(f"duplicate corpus id {item['id']!r}")
        if item["label"] == "benign" and item.get("expect_rules"):
            raise ValueError(f"{item['id']}: a benign entry cannot expect rules")
        seen.add(item["id"])
        entries.append(
            Entry(
                id=item["id"],
                label=item["label"],
                text=item["text"],
                rationale=item["rationale"],
                expect_rules=tuple(item.get("expect_rules", ())),
                known_limitation=item.get("known_limitation"),
            )
        )
    return entries


CORPUS = _load()
DETECTOR = InjectionDetector()


def _flagged(entry: Entry) -> tuple[bool, list[str]]:
    result = DETECTOR.scan(entry.text)
    return result.classification is not Classification.NORMAL, result.rule_ids


def test_the_corpus_is_large_enough_to_mean_something() -> None:
    """A corpus small enough to memorise measures nothing.

    The benign half carries the weight: it is what makes a widened pattern show
    up as a cost rather than a free improvement.
    """
    attacks = [e for e in CORPUS if e.label == "attack"]
    benign = [e for e in CORPUS if e.label == "benign"]
    assert len(attacks) >= 40, f"only {len(attacks)} attack entries"
    assert len(benign) >= 60, f"only {len(benign)} benign entries"


def test_every_default_rule_has_at_least_one_attack_entry() -> None:
    """A rule nobody exercises is a rule nobody can safely change."""
    covered = {rule for entry in CORPUS for rule in entry.expect_rules}
    missing = sorted(set(DETECTOR.rule_ids) - covered)
    assert not missing, f"default rules with no corpus entry: {missing}"


def test_precision_and_recall_meet_their_floors() -> None:
    """Report the confusion matrix, and name what moved when it fails."""
    scored = [e for e in CORPUS if e.known_limitation is None]
    false_positives: list[str] = []
    false_negatives: list[str] = []
    true_positives = 0

    for entry in scored:
        flagged, rules = _flagged(entry)
        if entry.label == "attack":
            if flagged:
                true_positives += 1
            else:
                false_negatives.append(f"  {entry.id}: {entry.rationale}")
        elif flagged:
            false_positives.append(f"  {entry.id}: fired {', '.join(rules)}")

    precision = true_positives / (true_positives + len(false_positives) or 1)
    recall = true_positives / (true_positives + len(false_negatives) or 1)

    report = [
        f"precision {precision:.3f} (floor {MIN_PRECISION:.2f}), "
        f"recall {recall:.3f} (floor {MIN_RECALL:.2f})",
        f"true positives {true_positives}, false positives "
        f"{len(false_positives)}, false negatives {len(false_negatives)}",
    ]
    if false_positives:
        report += ["", "NEW FALSE POSITIVES — benign text the detector flagged:"]
        report += false_positives
    if false_negatives:
        report += ["", "NEW FALSE NEGATIVES — attacks the detector missed:"]
        report += false_negatives
    detail = "\n".join(report)

    assert precision >= MIN_PRECISION, detail
    assert recall >= MIN_RECALL, detail


def test_known_limitations_still_behave_as_documented() -> None:
    """A known limitation that quietly starts passing must be un-recorded.

    Otherwise the docs keep warning about a weakness that no longer exists, and
    the exclusion list keeps hiding entries from the floors for no reason.
    """
    recovered = [
        f"  {entry.id}: {entry.known_limitation}"
        for entry in CORPUS
        if entry.known_limitation is not None
        and _flagged(entry)[0] is (entry.label == "attack")
    ]
    assert not recovered, (
        "these entries are recorded as known limitations but now behave "
        "correctly — remove the known_limitation field and update "
        "docs/DETECTION.md:\n" + "\n".join(recovered)
    )


@pytest.mark.parametrize(
    "entry", [e for e in CORPUS if e.expect_rules], ids=lambda e: e.id
)
def test_attacks_fire_the_rules_the_corpus_expects(entry: Entry) -> None:
    """Catching an attack by the wrong rule is a latent regression.

    If the entry survives only because some unrelated pattern happens to match,
    narrowing that pattern later silently reopens the hole.
    """
    _, rules = _flagged(entry)
    missing = [rule for rule in entry.expect_rules if rule not in rules]
    if entry.known_limitation is not None:
        return
    assert not missing, (
        f"{entry.id} expected {missing} but fired {rules or ['nothing']}"
    )


def test_the_corpus_carries_no_plausible_personal_data() -> None:
    """The corpus ships in the repository, so it must stay obviously fictional."""
    import re

    phone = re.compile(r"\+\d[\d ()-]{8,}")
    email = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}")
    offenders = []
    for entry in CORPUS:
        if phone.search(entry.text):
            offenders.append(f"{entry.id}: phone-shaped digits")
        for found in email.findall(entry.text):
            if not found.endswith((".example", ".invalid", ".test", ".internal")):
                offenders.append(f"{entry.id}: email-shaped {found}")
    assert not offenders, offenders
