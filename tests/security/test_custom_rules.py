"""Administrator-defined detection rules (PRD section 14)."""

from __future__ import annotations

import pytest

from pydantic import ValidationError

from mcp_telegram.config import ConfigError, load_config
from mcp_telegram.security.injection import InjectionDetector
from mcp_telegram.security.models import Classification, PatternRule


def test_custom_pattern_is_applied() -> None:
    detector = InjectionDetector(
        custom_patterns=[
            PatternRule(id="internal_codename", pattern="project (bluebird|redwood)")
        ]
    )
    result = detector.scan("Ask them about project bluebird")
    assert "internal_codename" in result.rule_ids
    assert result.classification is Classification.HIGH_RISK


def test_custom_pattern_is_case_insensitive_by_default() -> None:
    detector = InjectionDetector(
        custom_patterns=[PatternRule(id="x", pattern="SECRET")]
    )
    assert "x" in detector.scan("this is secret").rule_ids


def test_custom_pattern_can_be_case_sensitive() -> None:
    detector = InjectionDetector(
        custom_patterns=[PatternRule(id="x", pattern="SECRET", ignore_case=False)]
    )
    assert detector.scan("this is secret").rule_ids == []
    assert "x" in detector.scan("this is SECRET").rule_ids


def test_custom_pattern_risk_level_is_honoured() -> None:
    detector = InjectionDetector(
        custom_patterns=[PatternRule(id="x", pattern="maybe", risk="suspicious")]
    )
    assert detector.scan("maybe later").classification is Classification.SUSPICIOUS


def test_invalid_regex_is_rejected_with_a_clear_error() -> None:
    with pytest.raises(ValidationError) as excinfo:
        PatternRule(id="broken", pattern="(unclosed[")
    assert "invalid regular expression" in str(excinfo.value)


def test_invalid_regex_in_config_file_stops_startup(tmp_path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[[security.prompt_injection.custom_patterns]]\n"
        'id = "broken"\n'
        'pattern = "(unclosed["\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(config_file, environ={})
    assert "invalid regular expression" in str(excinfo.value)


def test_patterns_may_be_written_as_bare_strings(tmp_path) -> None:
    """The PRD shows a plain list of regexes; both spellings must work."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[security.prompt_injection]\n"
        'custom_patterns = ["ignore .* previous instructions", "reveal .* prompt"]\n',
        encoding="utf-8",
    )
    config = load_config(config_file, environ={})
    assert len(config.prompt_injection.custom_patterns) == 2
    assert config.prompt_injection.custom_patterns[0].id == "custom_1"


def test_duplicate_rule_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate detection rule id"):
        InjectionDetector(
            custom_patterns=[
                PatternRule(id="instruction_override", pattern="anything"),
            ]
        )


def test_patterns_are_compiled_once_at_initialisation() -> None:
    detector = InjectionDetector()
    compiled = [pattern for _, pattern in detector._rules]
    detector.scan("hello")
    detector.scan("world")
    assert [pattern for _, pattern in detector._rules] == compiled
