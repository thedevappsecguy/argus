"""Tests for argus.cli ADK-only wiring."""

import inspect
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli import app, build_report, run, suppress_known_adk_cli_warnings

runner = CliRunner()


def test_build_report_reads_text_document_and_calls_adk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    doc_path = tmp_path / "feature.md"
    doc_path.write_text("# Feature\nUsers can upload documents.\n", encoding="utf-8")

    def fake_run(input_text: str, source_name: str, **kwargs) -> str:
        calls.append((input_text, source_name, kwargs))
        return "# Threat Model: feature"

    monkeypatch.setattr("argus.cli.run_threat_model_adk", fake_run)
    report = build_report(str(doc_path))

    assert report == "# Threat Model: feature"
    assert calls == [
        (
            "# Feature\nUsers can upload documents.\n",
            str(doc_path),
            {"runtime_config": None, "progress_callback": None},
        )
    ]


def test_build_report_rejects_non_utf8_input(tmp_path: Path) -> None:
    import typer

    input_path = tmp_path / "binary.md"
    input_path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(typer.BadParameter, match="readable UTF-8 text document"):
        build_report(str(input_path))


def test_cli_run_has_no_type_option() -> None:
    parameters = inspect.signature(run).parameters
    assert "type" not in parameters
    assert {
        "path",
        "out",
        "model",
        "pro_model",
        "flash_model",
        "temperature",
        "no_progress",
    }.issubset(parameters)


def test_cli_suppresses_known_adk_experimental_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        "argus.cli.warnings.filterwarnings",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    suppress_known_adk_cli_warnings()

    assert calls == [
        (
            ("ignore",),
            {
                "message": (
                    r"\[EXPERIMENTAL\] feature "
                    r"FeatureName\.JSON_SCHEMA_FOR_FUNC_DECL is enabled\."
                ),
                "category": UserWarning,
                "module": r"google\.adk\.tools\.set_model_response_tool",
            },
        )
    ]


def test_cli_help_documents_flat_command_and_config_flags() -> None:
    result = runner.invoke(app, ["--help"], color=False)

    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert "PATH" in result.stdout
    assert "argus run" not in result.stdout


def test_cli_passes_resolved_config_and_progress_setting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    doc_path = tmp_path / "feature.md"
    out_path = tmp_path / "report.md"
    doc_path.write_text("# Feature\nUsers can upload documents.\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_run(input_text: str, source_name: str, **kwargs) -> str:
        calls.append((input_text, source_name, kwargs))
        return "# Threat Model: feature"

    monkeypatch.setattr("argus.cli.run_threat_model_adk", fake_run)

    result = runner.invoke(
        app,
        [
            str(doc_path),
            "--out",
            str(out_path),
            "--model",
            "gemini-cheap",
            "--temperature",
            "0.2",
            "--no-progress",
        ],
    )

    assert result.exit_code == 0
    assert out_path.read_text(encoding="utf-8") == "# Threat Model: feature"
    runtime_config = calls[0][2]["runtime_config"]
    assert runtime_config.pro_model == "gemini-cheap"
    assert runtime_config.flash_model == "gemini-cheap"
    assert runtime_config.temperature == 0.2
    assert calls[0][2].get("progress_callback") is None


def test_cli_specific_model_flags_override_model_shortcut(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    doc_path = tmp_path / "feature.md"
    doc_path.write_text("# Feature\nUsers can upload documents.\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_run(input_text: str, source_name: str, **kwargs) -> str:
        calls.append(kwargs["runtime_config"])
        return "# Threat Model: feature"

    monkeypatch.setattr("argus.cli.run_threat_model_adk", fake_run)

    result = runner.invoke(
        app,
        [
            str(doc_path),
            "--model",
            "gemini-cheap",
            "--pro-model",
            "gemini-pro",
            "--flash-model",
            "gemini-flash",
            "--no-progress",
        ],
    )

    assert result.exit_code == 0
    assert calls[0].pro_model == "gemini-pro"
    assert calls[0].flash_model == "gemini-flash"


def test_cli_fails_early_without_api_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    doc_path = tmp_path / "feature.md"
    doc_path.write_text("# Feature\nUsers can upload documents.\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    result = runner.invoke(app, [str(doc_path), "--no-progress"])

    assert result.exit_code != 0
    assert "GEMINI_API_KEY" in result.output
