import typer
from rich.console import Console
from rich.panel import Panel
from pathlib import Path
from typing import Optional

from config_loader import ConfigLoader
from scanner_ssh import SSHScanner
from scanner_ldap import LDAPScanner
from vault_client import VaultClient
from gap_analyzer import GapAnalyzer
from report_engine import ReportEngine

# Versión de la herramienta
__version__ = "1.0.0"

app = typer.Typer(help="VaultBlind: detecta cuentas privilegiadas no custodiadas en CyberArk")
console = Console()


@app.command()
def scan(
    mode: str = typer.Option("both", "--mode", "-m", help="Modo de escaneo: linux, ad o both"),
    config: Path = typer.Option(Path("config/lab.yaml"), "--config", "-c", help="Ruta al fichero YAML de configuración"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Fichero de salida (opcional)"),
    format: str = typer.Option("table", "--format", "-f", help="Formato de salida: json, csv o table"),
    mock: bool = typer.Option(False, "--mock", help="Usar servidor mock de PVWA local (http://localhost:8000)"),
):
    """Ejecuta el escaneo de cuentas privilegiadas y compara con la bóveda CyberArk."""
    try:
        # Mostrar cabecera de bienvenida
        console.print(Panel.fit(
            f"[bold cyan]VaultBlind v{__version__}[/bold cyan]\n"
            "Detector de cuentas privilegiadas no custodiadas",
            title="Inicio", border_style="cyan"
        ))

        # 1. Cargar configuración
        console.print("[yellow]» Cargando configuración...[/yellow]")
        cfg = ConfigLoader.load(config)
        console.print(f"[green]✓ Configuración cargada desde {config}[/green]")

        # 2. Escanear según el modo seleccionado
        discovered = []
        if mode in ("linux", "both"):
            console.print("[yellow]» Escaneando hosts Linux vía SSH...[/yellow]")
            ssh_scanner = SSHScanner(cfg)
            discovered.extend(ssh_scanner.scan())
            console.print(f"[green]✓ Descubiertas {len(discovered)} cuentas en Linux[/green]")

        if mode in ("ad", "both"):
            console.print("[yellow]» Escaneando Active Directory vía LDAP...[/yellow]")
            ldap_scanner = LDAPScanner(cfg)
            ad_accounts = ldap_scanner.scan()
            discovered.extend(ad_accounts)
            console.print(f"[green]✓ Descubiertas {len(ad_accounts)} cuentas en AD[/green]")

        # 3. Obtener cuentas custodiadas en CyberArk
        console.print("[yellow]» Consultando cuentas gestionadas en CyberArk...[/yellow]")
        vault = VaultClient(mock=mock)
        managed = vault.get_managed_accounts()
        console.print(f"[green]✓ {len(managed)} cuentas custodiadas en la bóveda[/green]")

        # 4. Analizar diferencias
        console.print("[yellow]» Analizando brechas de custodia...[/yellow]")
        gap_report = GapAnalyzer.analyze(discovered, managed)
        console.print(f"[green]✓ Análisis completado: {len(gap_report.missing)} cuentas sin custodia[/green]")

        # 5. Generar reporte
        console.print("[yellow]» Generando reporte...[/yellow]")
        ReportEngine.render(gap_report, format=format, output=output)
        if output:
            console.print(f"[green]✓ Reporte guardado en {output}[/green]")
        else:
            console.print("[green]✓ Reporte mostrado en terminal[/green]")

        # Resumen final
        console.print(Panel.fit(
            f"[bold]Resumen final[/bold]\n"
            f"Cuentas descubiertas: {len(discovered)}\n"
            f"Cuentas custodiadas: {len(managed)}\n"
            f"[red]Cuentas sin custodia: {len(gap_report.missing)}[/red]",
            title="Resultado", border_style="green" if not gap_report.missing else "red"
        ))

    except Exception as e:
        console.print_exception(show_locals=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
