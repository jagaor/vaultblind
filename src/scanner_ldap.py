import logging
from typing import List, Dict, Set, Optional

from ldap3 import Server, Connection, SIMPLE, ALL, SUBTREE, BASE
from ldap3.core.exceptions import LDAPException

from src.models import AccountRecord

logger = logging.getLogger(__name__)


class LDAPScanner:
    """Escanea un directorio Active Directory en busca de cuentas privilegiadas."""

    def __init__(
        self,
        server: str,
        port: int,
        base_dn: str,
        bind_user: str,
        bind_password: str,
        sensitive_groups: List[str],
    ) -> None:
        self.server = server
        self.port = port
        self.base_dn = base_dn
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.sensitive_groups = sensitive_groups

    def _connect(self) -> Connection:
        """Establece conexión LDAP con autenticación simple."""
        server = Server(self.server, port=self.port, get_info=ALL)
        conn = Connection(
            server,
            user=self.bind_user,
            password=self.bind_password,
            authentication=SIMPLE,
            auto_bind=True,
        )
        return conn

    def _search_admin_count(self, conn: Connection) -> List[Dict]:
        """Busca cuentas con AdminCount=1 y que no estén deshabilitadas."""
        filtro = (
            "(&(objectClass=user)(AdminCount=1)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        atributos = ["sAMAccountName", "distinguishedName", "memberOf"]
        conn.search(
            search_base=self.base_dn,
            search_filter=filtro,
            search_scope=SUBTREE,
            attributes=atributos,
        )
        return conn.entries

    def _search_group_members(self, conn: Connection, group_dn: str) -> List[Dict]:
        """Obtiene miembros de un grupo usando LDAP_MATCHING_RULE_IN_CHAIN."""
        filtro = (
            "(&(objectClass=user)"
            f"(memberOf:1.2.840.113556.1.4.1941:={group_dn})"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        atributos = ["sAMAccountName", "distinguishedName", "memberOf"]
        conn.search(
            search_base=self.base_dn,
            search_filter=filtro,
            search_scope=SUBTREE,
            attributes=atributos,
        )
        return conn.entries

    def _resolve_group_dn(self, conn: Connection, group_name: str) -> Optional[str]:
        """Resuelve el DN de un grupo a partir de su nombre común."""
        filtro = f"(&(objectClass=group)(cn={group_name}))"
        conn.search(
            search_base=self.base_dn,
            search_filter=filtro,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
        )
        if conn.entries:
            return str(conn.entries[0].distinguishedName)
        logger.warning("Grupo sensible no encontrado: %s", group_name)
        return None

    def _build_record(self, entry, extra_groups: Optional[List[str]] = None) -> AccountRecord:
        """Construye un AccountRecord a partir de una entrada LDAP."""
        username = str(entry.sAMAccountName) if entry.sAMAccountName else ""
        dn = str(entry.distinguishedName) if entry.distinguishedName else ""
        groups = [str(g) for g in entry.memberOf] if entry.memberOf else []
        if extra_groups:
            groups = list(set(groups + extra_groups))
        admin_count = getattr(entry, "adminCount", None)
        admin_count_val = int(admin_count.value) if admin_count and admin_count.value else 0
        return AccountRecord(
            username=username,
            source="active_directory",
            host=self.base_dn,
            group=",".join(groups) if groups else None,
            extra={
                "dn": dn,
                "groups": groups,
                "admin_count": admin_count_val,
            },
        )

    def scan(self) -> List[AccountRecord]:
        """Ejecuta el escaneo completo y devuelve las cuentas privilegiadas."""
        records: Dict[str, AccountRecord] = {}
        try:
            conn = self._connect()
        except LDAPException as exc:
            logger.error("Error de conexión LDAP: %s", exc)
            return []

        try:
            for entry in self._search_admin_count(conn):
                rec = self._build_record(entry)
                records[rec.extra["dn"]] = rec

            for group_name in self.sensitive_groups:
                group_dn = self._resolve_group_dn(conn, group_name)
                if not group_dn:
                    continue
                for entry in self._search_group_members(conn, group_dn):
                    rec = self._build_record(entry, extra_groups=[group_name])
                    dn = rec.extra["dn"]
                    if dn in records:
                        existing = records[dn]
                        merged = set(existing.extra["groups"]) | set(rec.extra["groups"])
                        existing.extra["groups"] = sorted(merged)
                        existing.group = ",".join(sorted(merged))
                    else:
                        records[dn] = rec
        except LDAPException as exc:
            logger.error("Error durante la búsqueda LDAP: %s", exc)
        finally:
            conn.unbind()

        return list(records.values())
