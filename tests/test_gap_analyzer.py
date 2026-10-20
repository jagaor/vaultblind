import pytest
from src.models import AccountRecord, GapReport
from src.gap_analyzer import GapAnalyzer


def test_gap_vacio_cuando_todas_cuentas_estan_managed():
    scanned = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="admin", host="host-b", source="linux"),
    ]
    managed = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="admin", host="host-b", source="linux"),
    ]
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    assert len(report.gaps) == 0


def test_gap_correcto_con_tres_scanned_y_una_managed():
    scanned = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="admin", host="host-b", source="linux"),
        AccountRecord(username="user", host="host-c", source="linux"),
    ]
    managed = [
        AccountRecord(username="root", host="host-a", source="linux"),
    ]
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    assert len(report.gaps) == 2
    assert {g.username for g in report.gaps} == {"admin", "user"}


def test_matching_case_insensitive():
    scanned = [
        AccountRecord(username="ROOT", host="host-a", source="linux"),
    ]
    managed = [
        AccountRecord(username="root", host="host-a", source="linux"),
    ]
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    assert len(report.gaps) == 0


def test_mismo_username_distinto_host_no_son_iguales():
    scanned = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="root", host="host-b", source="linux"),
    ]
    managed = [
        AccountRecord(username="root", host="host-a", source="linux"),
    ]
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    assert len(report.gaps) == 1
    assert report.gaps[0].host == "host-b"


def test_summary_tiene_campos_correctos_y_totales_coherentes():
    scanned = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="admin", host="host-b", source="linux"),
        AccountRecord(username="user", host="host-c", source="linux"),
    ]
    managed = [
        AccountRecord(username="root", host="host-a", source="linux"),
    ]
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    summary = report.summary()
    assert summary["total_scanned"] == 3
    assert summary["total_managed"] == 1
    assert summary["total_gaps"] == 2
    assert summary["by_source"] == {"linux": 2}


def test_summary_detalla_fuentes_distintas():
    scanned = [
        AccountRecord(username="root", host="host-a", source="linux"),
        AccountRecord(username="admin", host="domain", source="active_directory"),
    ]
    managed = []
    analyzer = GapAnalyzer()
    report = analyzer.analyze(scanned, managed)
    summary = report.summary()
    assert summary["total_gaps"] == 2
    assert summary["by_source"] == {"linux": 1, "active_directory": 1}
