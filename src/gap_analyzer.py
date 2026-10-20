from typing import List, Set, Tuple

from src.models import AccountRecord, GapReport


def _identity_key(record: AccountRecord) -> Tuple[str, str]:
    """Construye la clave de identidad (username, host) en minúsculas.

    El host o dominio se normaliza a minúsculas para evitar falsos
    positivos por diferencias de capitalización entre el inventario
    descubierto y la bóveda CyberArk.
    """
    username = (record.username or "").strip().lower()
    host = (record.host or "").strip().lower()
    return username, host


class GapAnalyzer:
    """Compara cuentas descubiertas contra cuentas custodiadas en la bóveda."""

    @staticmethod
    def analyze(scanned: List[AccountRecord], managed: List[AccountRecord]) -> GapReport:
        """Calcula el conjunto de cuentas privilegiadas sin custodia.

        El gap se obtiene como diferencia de conjuntos sobre la tupla
        (username, host) normalizada. El resultado conserva los objetos
        AccountRecord originales del inventario escaneado.
        """
        scanned_set: Set[Tuple[str, str]] = {_identity_key(r) for r in scanned}
        managed_set: Set[Tuple[str, str]] = {_identity_key(r) for r in managed}

        gap_keys: Set[Tuple[str, str]] = scanned_set - managed_set

        # Recuperamos los objetos originales para preservar metadatos
        # (grupo, origen, timestamp) en el reporte final.
        gap_records: List[AccountRecord] = [
            record for record in scanned if _identity_key(record) in gap_keys
        ]

        # Desglose del gap por origen del descubrimiento.
        summary = {
            "linux": sum(1 for r in gap_records if r.source == "linux"),
            "active_directory": sum(
                1 for r in gap_records if r.source == "active_directory"
            ),
        }

        return GapReport.from_lists(
            scanned=scanned,
            managed=managed,
            gap=gap_records,
            summary=summary,
        )
