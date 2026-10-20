import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.models import GapReport


class ReportEngine:
    """Motor de generación de informes de gaps de custodia.

    Soporta salida en tabla (Rich), JSON y CSV. Si se indica output_path,
    el informe se escribe en disco además de mostrarse por consola.
    """

    _console = Console()

    @staticmethod
    def render(report: GapReport, format: str = "table", output_path: Optional[str] = None) -> None:
        """Renderiza el informe en el formato solicitado."""
        fmt = (format or "table").lower()
        if fmt == "table":
            ReportEngine._render_table(report, output_path)
        elif fmt == "json":
            ReportEngine._render_json(report, output_path)
        elif fmt == "csv":
            ReportEngine._render_csv(report, output_path)
        else:
            raise ValueError(f"Formato de salida no soportado: {format!r}")

    @staticmethod
    def _render_table(report: GapReport, output_path: Optional[str]) -> None:
        """Muestra el informe como tabla Rich en consola."""
        console = ReportEngine._console
        console.print(Panel.fit(
            f"VaultBlind - Informe de gaps de custodia\nGenerado: {datetime.utcnow().isoformat()}Z",
            title="VaultBlind",
        ))

        detalle = Table(title="Cuentas privilegiadas no custodiadas", show_lines=False)
        detalle.add_column("Username", style="cyan", no_wrap=True)
        detalle.add_column("Origen", style="magenta")
        detalle.add_column("Host", style="green")
        detalle.add_column("Grupos", style="yellow")

        for gap in report.gaps:
            grupos = ", ".join(gap.groups) if gap.groups else "-"
            detalle.add_row(gap.username, gap.source, gap.host, grupos)

        console.print(detalle)

        resumen = Table(title="Resumen por origen")
        resumen.add_column("Origen", style="magenta")
        resumen.add_column("Halladas", justify="right")
        resumen.add_column("En bóveda", justify="right")
        resumen.add_column("GAP", justify="right", style="bold red")

        for origen, stats in report.summary.items():
            resumen.add_row(
                origen,
                str(stats.get("discovered", 0)),
                str(stats.get("vaulted", 0)),
                str(stats.get("gap", 0)),
            )

        console.print(resumen)

        if output_path:
            # Volcado textual del mismo contenido para trazabilidad en disco
            with open(output_path, "w", encoding="utf-8") as fh:
                for gap in report.gaps:
                    fh.write(f"{gap.username}\t{gap.source}\t{gap.host}\t{','.join(gap.groups)}\n")
            console.print(f"[dim]Informe textual escrito en {output_path}[/dim]")

    @staticmethod
    def _render_json(report: GapReport, output_path: Optional[str]) -> None:
        """Serializa el informe a JSON y lo escribe o imprime."""
        payload = report.to_dict()
        texto = json.dumps(payload, indent=2, ensure_ascii=False)

        if output_path:
            Path(output_path).write_text(texto, encoding="utf-8")
            ReportEngine._console.print(f"[dim]Informe JSON escrito en {output_path}[/dim]")
        else:
            sys.stdout.write(texto + "\n")

    @staticmethod
    def _render_csv(report: GapReport, output_path: Optional[str]) -> None:
        """Escribe el informe en CSV con campos normalizados."""
        campos = ["username", "source", "host", "extra"]
        filas = []
        for gap in report.gaps:
            filas.append({
                "username": gap.username,
                "source": gap.source,
                "host": gap.host,
                "extra": json.dumps({"groups": gap.groups}, ensure_ascii=False),
            })

        destino = output_path if output_path else None
        if destino:
            with open(destino, "w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=campos)
                writer.writeheader()
                writer.writerows(filas)
            ReportEngine._console.print(f"[dim]Informe CSV escrito en {destino}[/dim]")
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=campos)
            writer.writeheader()
            writer.writerows(filas)
