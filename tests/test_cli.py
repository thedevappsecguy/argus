"""Tests for argus.cli ADK-only wiring."""

import inspect
from pathlib import Path

import pytest

from argus.cli import build_report, run


def test_build_report_reads_text_document_and_calls_adk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    doc_path = tmp_path / "feature.md"
    doc_path.write_text("# Feature\nUsers can upload documents.\n", encoding="utf-8")

    def fake_run(input_text: str, source_name: str) -> str:
        calls.append((input_text, source_name))
        return "# Threat Model: feature"

    monkeypatch.setattr("argus.cli.run_threat_model_adk", fake_run)
    report = build_report(str(doc_path))

    assert report == "# Threat Model: feature"
    assert calls == [("# Feature\nUsers can upload documents.\n", str(doc_path))]


def test_build_report_rejects_non_utf8_input(tmp_path: Path) -> None:
    import typer

    input_path = tmp_path / "binary.md"
    input_path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(typer.BadParameter, match="readable UTF-8 text document"):
        build_report(str(input_path))


def test_cli_run_has_no_type_option() -> None:
    assert "type" not in inspect.signature(run).parameters
