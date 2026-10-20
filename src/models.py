import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, List, Dict, Any, Optional


@dataclass
class AccountRecord:
    """Representa una cuenta privilegiada descubierta en un sistema."""
    username: str
    source: Literal['linux', 'active_directory']
    host: str
    extra: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def identity_key(self) -> tuple:
        """Clave de identidad para comparar cuentas entre fuentes."""
        return (self.username, self.host)


@dataclass
class GapReport:
    """Resultado del análisis de brechas entre cuentas descubiertas y custodiadas."""
    scanned: List[AccountRecord]
    managed: List[AccountRecord]
    gap: List[AccountRecord]
    summary: Dict[str, Any]

    @classmethod
    def from_lists(cls, scanned: List[AccountRecord], managed: List[AccountRecord]) -> 'GapReport':
        """Calcula el gap y el resumen a partir de las listas de cuentas."""
        managed_keys = {acc.identity_key() for acc in managed}
        gap = [acc for acc in scanned if acc.identity_key() not in managed_keys]

        # Resumen por fuente
        by_source: Dict[str, int] = {}
        for acc in scanned:
            by_source[acc.source] = by_source.get(acc.source, 0) + 1

        summary = {
            'total_scanned': len(scanned),
            'total_managed': len(managed),
            'total_gap': len(gap),
            'by_source': by_source,
        }
        return cls(scanned=scanned, managed=managed, gap=gap, summary=summary)


@dataclass
class ConfigSchema:
    """Esquema de configuración cargado desde YAML."""
    hosts: List[Dict[str, Any]]
    ldap: Dict[str, Any]
    vault: Dict[str, Any]

    def __post_init__(self):
        """Valida que los campos obligatorios estén presentes."""
        if not isinstance(self.hosts, list):
            raise ValueError('hosts debe ser una lista')
        if not isinstance(self.ldap, dict):
            raise ValueError('ldap debe ser un diccionario')
        if not isinstance(self.vault, dict):
            raise ValueError('vault debe ser un diccionario')
