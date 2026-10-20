"""Mock server FastAPI que emula los endpoints de CyberArk PVWA REST API.

Se usa en el laboratorio cuando no hay acceso a una instancia real de CyberArk.
Arranque directo: python src/mock_pvwa.py
"""

from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Query, Request

app = FastAPI(title="Mock PVWA", version="0.1.0")

# Token de laboratorio que devuelve el endpoint de Logon
MOCK_TOKEN = "mock-token-abc123"

# Catálogo de cuentas custodiadas simuladas. Coherente con config/lab.yaml.example:
# root en lab-linux-01 está custodiada, deploy en lab-linux-01 no lo está, etc.
MOCK_ACCOUNTS: List[Dict[str, Any]] = [
    {"id": "1001", "userName": "root", "address": "lab-linux-01", "platformId": "UnixSSH", "safeName": "Linux-Root", "accountType": "Password"},
    {"id": "1002", "userName": "svc_backup", "address": "lab-linux-01", "platformId": "UnixSSH", "safeName": "Linux-Svc", "accountType": "Password"},
    {"id": "1003", "userName": "root", "address": "lab-linux-02", "platformId": "UnixSSH", "safeName": "Linux-Root", "accountType": "Password"},
    {"id": "1004", "userName": "monitor", "address": "lab-linux-02", "platformId": "UnixSSH", "safeName": "Linux-Svc", "accountType": "Password"},
    {"id": "1005", "userName": "ansible", "address": "lab-linux-03", "platformId": "UnixSSH", "safeName": "Linux-Automation", "accountType": "Password"},
    {"id": "1006", "userName": "root", "address": "lab-linux-03", "platformId": "UnixSSH", "safeName": "Linux-Root", "accountType": "Password"},
    {"id": "1007", "userName": "Administrator", "address": "lab-dc-01.lab.local", "platformId": "WinDomain", "safeName": "AD-Admins", "accountType": "Password"},
    {"id": "1008", "userName": "svc_sql", "address": "lab-dc-01.lab.local", "platformId": "WinDomain", "safeName": "AD-Svc", "accountType": "Password"},
    {"id": "1009", "userName": "backup_admin", "address": "lab-dc-01.lab.local", "platformId": "WinDomain", "safeName": "AD-Admins", "accountType": "Password"},
    {"id": "1010", "userName": "jdoe", "address": "lab-dc-01.lab.local", "platformId": "WinDomain", "safeName": "AD-Users", "accountType": "Password"},
    {"id": "1011", "userName": "deploy", "address": "lab-linux-04", "platformId": "UnixSSH", "safeName": "Linux-Automation", "accountType": "Password"},
    {"id": "1012", "userName": "root", "address": "lab-linux-04", "platformId": "UnixSSH", "safeName": "Linux-Root", "accountType": "Password"},
    {"id": "1013", "userName": "oracle", "address": "lab-db-01", "platformId": "UnixSSH", "safeName": "DB-Accounts", "accountType": "Password"},
    {"id": "1014", "userName": "postgres", "address": "lab-db-01", "platformId": "UnixSSH", "safeName": "DB-Accounts", "accountType": "Password"},
    {"id": "1015", "userName": "svc_jenkins", "address": "lab-ci-01", "platformId": "UnixSSH", "safeName": "Linux-Automation", "accountType": "Password"},
    {"id": "1016", "userName": "root", "address": "lab-ci-01", "platformId": "UnixSSH", "safeName": "Linux-Root", "accountType": "Password"},
    {"id": "1017", "userName": "helpdesk", "address": "lab-dc-01.lab.local", "platformId": "WinDomain", "safeName": "AD-Helpdesk", "accountType": "Password"},
    {"id": "1018", "userName": "svc_monitor", "address": "lab-linux-02", "platformId": "UnixSSH", "safeName": "Linux-Svc", "accountType": "Password"},
]


def _aplicar_filtro(cuentas: List[Dict[str, Any]], filtro: Optional[str]) -> List[Dict[str, Any]]:
    """Aplica un filtro estilo PVWA (pares clave=valor separados por espacios)."""
    if not filtro:
        return cuentas

    resultado = cuentas
    for par in filtro.split():
        if "=" not in par:
            continue
        clave, valor = par.split("=", 1)
        clave = clave.strip()
        valor = valor.strip().strip("'\"")
        resultado = [c for c in resultado if str(c.get(clave, "")) == valor]
    return resultado


@app.post("/api/auth/CyberArk/Logon")
async def logon(request: Request) -> Dict[str, str]:
    """Devuelve un token fijo sin validar credenciales (entorno de laboratorio)."""
    _ = await request.json()
    return {"CyberArkLogonResult": MOCK_TOKEN}


@app.post("/api/auth/Logoff")
async def logoff() -> Dict[str, str]:
    """Cierre de sesión simulado."""
    return {"status": "ok"}


@app.get("/api/Accounts")
async def listar_cuentas(
    filter: Optional[str] = Query(default=None, description="Filtro estilo PVWA, ej: userName=root"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """Devuelve la lista paginada de cuentas custodiadas simuladas."""
    filtradas = _aplicar_filtro(MOCK_ACCOUNTS, filter)
    pagina = filtradas[offset:offset + limit]
    return {
        "value": pagina,
        "count": len(pagina),
        "total": len(filtradas),
    }


if __name__ == "__main__":
    # Arranque de laboratorio en el puerto 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)
