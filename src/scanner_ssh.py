import logging
from typing import List, Dict, Optional

import paramiko
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException

from src.models import AccountRecord

logger = logging.getLogger(__name__)


class SSHScanner:
    """Escáner de cuentas privilegiadas en hosts Linux vía SSH."""

    def __init__(self, hosts: List[Dict]):
        """
        Inicializa el escáner con la lista de hosts.
        Cada host es un dict con claves: hostname, ip, port (default 22),
        username, password (opcional), key_path (opcional).
        """
        self.hosts = hosts

    def _connect(self, host: Dict) -> Optional[SSHClient]:
        """Establece conexión SSH con un host. Devuelve None si falla."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            client.connect(
                hostname=host["ip"],
                port=host.get("port", 22),
                username=host["username"],
                password=host.get("password"),
                key_filename=host.get("key_path"),
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            return client
        except AuthenticationException:
            logger.warning("Autenticación fallida en host %s (%s)", host.get("hostname"), host["ip"])
        except (SSHException, OSError) as exc:
            logger.warning("Error de conexión SSH a %s (%s): %s", host.get("hostname"), host["ip"], exc)
        finally:
            if client.get_transport() is not None and not client.get_transport().is_active():
                client.close()
        return None

    def _exec(self, client: SSHClient, command: str) -> str:
        """Ejecuta un comando remoto y devuelve la salida estándar."""
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=10)
            return stdout.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Error ejecutando comando '%s': %s", command, exc)
            return ""

    def _parse_passwd(self, output: str) -> List[Dict]:
        """Parsea /etc/passwd y devuelve cuentas con shell válida (excepto root)."""
        cuentas = []
        for linea in output.splitlines():
            partes = linea.strip().split(":")
            if len(partes) < 7:
                continue
            username, _, uid, _, _, _, shell = partes[:7]
            if not uid.isdigit():
                continue
            uid_int = int(uid)
            # Incluir root siempre; para el resto, solo UID >= 1000 y shell válida
            if username == "root":
                cuentas.append({"username": username, "shell": shell, "uid": uid_int})
                continue
            if uid_int < 1000:
                continue
            if shell in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                continue
            cuentas.append({"username": username, "shell": shell, "uid": uid_int})
        return cuentas

    def _parse_sudoers(self, output: str) -> List[str]:
        """Extrae nombres de usuario de líneas de /etc/sudoers."""
        usuarios = []
        for linea in output.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or linea.startswith("Defaults"):
                continue
            # Formato típico: usuario ALL=(ALL) ALL
            partes = linea.split()
            if len(partes) >= 2 and "ALL" in linea:
                usuario = partes[0]
                if usuario not in ("%sudo", "%wheel", "%admin") and not usuario.startswith("%"):
                    usuarios.append(usuario)
        return usuarios

    def _parse_groups(self, output: str) -> List[str]:
        """Extrae miembros de grupos privilegiados desde getent group."""
        miembros = []
        for linea in output.splitlines():
            partes = linea.strip().split(":")
            if len(partes) >= 4 and partes[3]:
                miembros.extend(partes[3].split(","))
        return miembros

    def scan(self) -> List[AccountRecord]:
        """Escanea todos los hosts y devuelve los registros de cuentas privilegiadas."""
        registros: List[AccountRecord] = []

        for host in self.hosts:
            hostname = host.get("hostname", host["ip"])
            client = self._connect(host)
            if client is None:
                continue

            try:
                passwd_out = self._exec(client, "cat /etc/passwd")
                cuentas = self._parse_passwd(passwd_out)

                sudoers_out = self._exec(client, "sudo cat /etc/sudoers 2>/dev/null")
                sudoers_users = set(self._parse_sudoers(sudoers_out))

                # Leer /etc/sudoers.d/
                sudoers_d_out = self._exec(client, "sudo cat /etc/sudoers.d/* 2>/dev/null")
                sudoers_users.update(self._parse_sudoers(sudoers_d_out))

                groups_out = self._exec(client, "getent group sudo wheel admin 2>/dev/null")
                group_members = set(self._parse_groups(groups_out))

                for cuenta in cuentas:
                    username = cuenta["username"]
                    grupos = []
                    if username in sudoers_users:
                        grupos.append("sudoers")
                    if username in group_members:
                        grupos.append("grupo_privilegiado")
                    if username == "root":
                        grupos.append("root")

                    if grupos:
                        registros.append(
                            AccountRecord(
                                username=username,
                                source="linux",
                                host=hostname,
                                extra={"groups": grupos, "shell": cuenta["shell"]},
                            )
                        )
            except Exception as exc:
                logger.warning("Error escaneando host %s: %s", hostname, exc)
            finally:
                client.close()

        return registros
