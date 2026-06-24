"""Argus CLI: ``argus run <input> [--out]``."""

import pathlib

import typer

from argus.agents.runner import run_threat_model_adk

app = typer.Typer(help="Argus - ADK threat-modeling agent")


def build_report(path: str) -> str:
    """Read a UTF-8 document and run the ADK threat-model workflow."""
    p = pathlib.Path(path)
    try:
        input_text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise typer.BadParameter("Input must be a readable UTF-8 text document.") from exc

    return run_threat_model_adk(input_text, str(p))


@app.command()
def run(
    path: str = typer.Argument(
        ..., help="Input document: PRD, design doc, feature doc, RFC, or ADR"
    ),
    out: str | None = typer.Option(
        None, "--out", help="Output path (default: <input>.threatmodel.md)"
    ),
) -> None:
    """Run the Argus ADK threat-modeling workflow on an input file."""
    report = build_report(path)
    out_path = pathlib.Path(out or f"{path}.threatmodel.md")
    out_path.write_text(report, encoding="utf-8")
    typer.echo(f"Wrote threat model -> {out_path}")


def main() -> None:
    """Entry point for the ``argus`` console script."""
    app()


if __name__ == "__main__":
    main()
