"""Argus CLI: ``argus <input> [--out]``."""

from __future__ import annotations

import pathlib
import warnings
from types import TracebackType

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from argus import config
from argus.agents.adk_app import STAGE_NAMES
from argus.agents.runner import ProgressCallback, run_threat_model_adk

app = typer.Typer(help="Argus - ADK threat-modeling agent")

STAGE_LABELS = {
    "ingestion_agent": "Ingesting document",
    "architecture_zone_agent": "Mapping architecture zones",
    "entry_point_agent": "Identifying entry points",
    "scenario_enumeration_agent": "Enumerating attack scenarios",
    "schema_validation_agent": "Validating threat schema",
    "element_binding_agent": "Binding threats to model elements",
    "false_positive_validation_agent": "Validating attack reachability",
    "control_challenge_agent": "Challenging controls",
    "risk_rating_agent": "Rating risk",
    "report_agent": "Rendering report",
}


def suppress_known_adk_cli_warnings() -> None:
    """Hide known ADK experimental feature noise from normal CLI output."""
    warnings.filterwarnings(
        "ignore",
        message=(
            r"\[EXPERIMENTAL\] feature "
            r"FeatureName\.JSON_SCHEMA_FOR_FUNC_DECL is enabled\."
        ),
        category=UserWarning,
        module=r"google\.adk\.tools\.set_model_response_tool",
    )


class CliProgress:
    """Small Rich wrapper for ADK stage progress."""

    def __init__(self, *, disabled: bool = False):
        self.disabled = disabled
        self.console = Console(stderr=True)
        self._progress: Progress | None = None
        self._task_id: TaskID | None = None
        self._completed: set[str] = set()

    @property
    def enabled(self) -> bool:
        return not self.disabled

    def __enter__(self) -> CliProgress:
        if self.disabled:
            return self
        if self.console.is_terminal:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=self.console,
            )
            self._progress.start()
            self._task_id = self._progress.add_task(
                "Starting Argus workflow",
                total=len(STAGE_NAMES),
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.stop()

    def callback(self, stage: str, status: str) -> None:
        if self.disabled:
            return

        label = STAGE_LABELS.get(stage, stage.replace("_", " "))
        if status == "started":
            self._stage_started(stage, label)
        elif status == "completed":
            self._stage_completed(stage, label)
        elif status == "failed":
            self._stage_failed(stage, label)

    def _stage_started(self, stage: str, label: str) -> None:
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, description=label)
            return
        index = STAGE_NAMES.index(stage) + 1 if stage in STAGE_NAMES else "?"
        self.console.print(f"[{index}/{len(STAGE_NAMES)}] {label}")

    def _stage_completed(self, stage: str, label: str) -> None:
        if stage in self._completed:
            return
        self._completed.add(stage)
        if self._progress is not None and self._task_id is not None:
            self._progress.advance(self._task_id)
            self._progress.update(self._task_id, description=label)

    def _stage_failed(self, stage: str, label: str) -> None:
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, description=f"Failed: {label}")
            return
        self.console.print(f"Failed: {label}")


def build_report(
    path: str,
    *,
    runtime_config: config.RuntimeConfig | None = None,
    progress_callback: ProgressCallback | None = None,
) -> str:
    """Read a UTF-8 document and run the ADK threat-model workflow."""
    p = pathlib.Path(path)
    try:
        input_text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise typer.BadParameter("Input must be a readable UTF-8 text document.") from exc

    return run_threat_model_adk(
        input_text,
        str(p),
        runtime_config=runtime_config,
        progress_callback=progress_callback,
    )


@app.command()
def run(
    path: str = typer.Argument(
        ..., help="Input document: PRD, design doc, feature doc, RFC, or ADR"
    ),
    out: str | None = typer.Option(
        None, "--out", help="Output path (default: <input>.threatmodel.md)"
    ),
    model: str | None = typer.Option(
        None, "--model", help="Use one model for all Argus agent stages"
    ),
    pro_model: str | None = typer.Option(
        None, "--pro-model", help="Model for deeper reasoning stages"
    ),
    flash_model: str | None = typer.Option(None, "--flash-model", help="Model for lighter stages"),
    temperature: float | None = typer.Option(
        None, "--temperature", help="Generation temperature (default: 0.1)"
    ),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable stage progress output"),
) -> None:
    """Run the Argus ADK threat-modeling workflow on an input file."""
    suppress_known_adk_cli_warnings()
    try:
        runtime_config = config.resolve_runtime_config(
            model=model,
            pro_model=pro_model,
            flash_model=flash_model,
            temperature=temperature,
        )
    except ValueError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not runtime_config.api_key:
        typer.echo(
            "GEMINI_API_KEY is required. Set it in the environment or a .env file.",
            err=True,
        )
        raise typer.Exit(1)

    out_path = pathlib.Path(out or f"{path}.threatmodel.md")
    with CliProgress(disabled=no_progress) as progress:
        progress_callback = progress.callback if progress.enabled else None
        report = build_report(
            path,
            runtime_config=runtime_config,
            progress_callback=progress_callback,
        )
    out_path.write_text(report, encoding="utf-8")
    typer.echo(f"Wrote threat model -> {out_path}")


def main() -> None:
    """Entry point for the ``argus`` console script."""
    suppress_known_adk_cli_warnings()
    app()


if __name__ == "__main__":
    main()
