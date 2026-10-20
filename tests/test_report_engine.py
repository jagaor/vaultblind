import io
import json

import pytest
from rich.console import Console

from src.gap_analyzer import GapReport
from src.models import AccountRecord
from src.report_engine import ReportEngine


@pytest.fixture
def gap_report():
    """GapReport de ejemplo con 3 cuentas no custodiadas: 2 linux y 1 ad."""
    gap = [
        AccountRecord(username="root", origen="linux", host="srv01.lab.local", grupo="sudo", timestamp="2024-01-01T00:00:00"),
        AccountRecord(username="deploy", origen="linux", host="srv02.lab.local", grupo="sudoers", timestamp="2024-01-01T00:00:00"),
        AccountRecord(username="svc_backup", origen="ad", host="lab.local", grupo="Backup Operators", timestamp="2024-01-01T00:00:00"),
    ]
    scanned = gap + [
        AccountRecord(username="admin_vault", origen="ad", host="lab.local", grupo="Domain Admins", timestamp="2024-01-01T00:00:00"),
    ]
    return GapReport(gap=gap, scanned=scanned)


def test_render_json_escribe_fichero(tmp_path, gap_report):
    """El formato json con output_path crea el fichero con gap, summary y scanned."""
    destino = tmp_path / "report.json"
    engine = ReportEngine(console=Console(file=io.StringIO()))
    engine.render(gap_report, format="json", output_path=str(destino))

    assert destino.exists()
    datos = json.loads(destino.read_text(encoding="utf-8"))
    assert "gap" in datos
    assert "summary" in datos
    assert "scanned" in datos
    assert len(datos["gap"]) == 3


def test_render_csv_cabecera_y_filas(tmp_path, gap_report):
    """El formato csv genera cabecera correcta y una fila por cuenta del gap."""
    destino = tmp_path / "report.csv"
    engine = ReportEngine(console=Console(file=io.StringIO()))
    engine.render(gap_report, format="csv", output_path=str(destino))

    lineas = destino.read_text(encoding="utf-8").strip().splitlines()
    cabecera = lineas[0].split(",")
    assert "username" in cabecera
    assert "origen" in cabecera
    assert "host" in cabecera
    assert len(lineas) - 1 == len(gap_report.gap)


def test_render_table_no_lanza_excepcion(gap_report):
    """El formato table se renderiza en un Console en memoria sin errores."""
    buffer = io.StringIO()
    engine = ReportEngine(console=Console(file=buffer))
    engine.render(gap_report, format="table")
    assert buffer.getvalue() != ""


def test_render_json_sin_output_path_imprime_stdout(capsys, gap_report):
    """El formato json sin output_path imprime el JSON en stdout."""
    engine = ReportEngine(console=Console(file=io.StringIO()))
    engine.render(gap_report, format="json")

    salida = capsys.readouterr().out
    datos = json.loads(salida)
    assert "gap" in datos
    assert "summary" in datos
    assert "scanned" in datos
