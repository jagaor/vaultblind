import os
from typing import List, Optional

import httpx

from src.models import AccountRecord


class VaultClient:
    """Cliente para interactuar con la API REST de CyberArk PVWA.

    Encapsula autenticación y consulta de cuentas custodiadas en la bóveda.
    Cuando mock=True, apunta al servidor de laboratorio que emula PVWA.
    """

    def __init__(
        self,
        base_url: str,
        app_id: str,
        username: str,
        password: str,
        mock: bool = False,
    ) -> None:
        # En modo mock se fuerza la URL del servidor FastAPI local
        if mock:
            base_url = "http://localhost:8000"
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id
        self.username = username
        self.password = password
        self.mock = mock
        self.token: Optional[str] = None
        self._client = httpx.Client(base_url=self.base_url, timeout=30.0)

    def authenticate(self) -> str:
        """Autentica contra PVWA y almacena el token de sesión."""
        payload = {"username": self.username, "password": self.password}
        response = self._client.post("/api/auth/CyberArk/Logon", json=payload)
        response.raise_for_status()
        # PVWA devuelve el token como cadena JSON (a veces envuelto en comillas)
        token = response.text.strip().strip('"')
        if not token:
            raise RuntimeError("PVWA no devolvió un token de sesión válido")
        self.token = token
        return token

    def _ensure_token(self) -> str:
        """Garantiza que existe un token antes de consultar la API."""
        if not self.token:
            return self.authenticate()
        return self.token

    def get_managed_accounts(self, safe_name: Optional[str] = None) -> List[AccountRecord]:
        """Recupera todas las cuentas custodiadas, paginando hasta agotar resultados."""
        token = self._ensure_token()
        headers = {"Authorization": f"Bearer {token}"}
        params = {}
        if safe_name:
            params["filter"] = f"safeName eq '{safe_name}'"

        accounts: List[AccountRecord] = []
        next_url: Optional[str] = "/api/Accounts"

        while next_url:
            response = self._client.get(next_url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            for item in data.get("value", []):
                platform = item.get("platformId", "") or ""
                source = "linux" if platform.startswith("Unix") else "active_directory"
                accounts.append(
                    AccountRecord(
                        username=item.get("userName", ""),
                        source=source,
                        host=item.get("address", ""),
                        extra={
                            "safe": item.get("safeName"),
                            "id": item.get("id"),
                        },
                    )
                )

            # nextLink puede venir como ruta relativa o URL absoluta
            next_url = data.get("nextLink")
            # Tras la primera página, los filtros ya van embebidos en nextLink
            params = {}

        return accounts

    def close(self) -> None:
        """Cierra el cliente HTTP subyacente."""
        self._client.close()

    def __enter__(self) -> "VaultClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def load_vault_client_from_config(config: dict, mock: bool) -> VaultClient:
    """Construye un VaultClient a partir del dict de configuración.

    Los secretos se leen de variables de entorno para no persistirlos en disco.
    """
    pvwa = config.get("pvwa", {})
    base_url = pvwa.get("base_url", "")
    app_id = pvwa.get("app_id", "")

    username = os.environ.get("VAULTBLIND_PVWA_USER", pvwa.get("username", ""))
    password = os.environ.get("VAULTBLIND_PVWA_PASSWORD", "")

    if not mock and not password:
        raise ValueError(
            "Falta la contraseña de PVWA: define VAULTBLIND_PVWA_PASSWORD"
        )

    return VaultClient(
        base_url=base_url,
        app_id=app_id,
        username=username,
        password=password,
        mock=mock,
    )
