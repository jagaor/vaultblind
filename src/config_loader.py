import os
import re
from typing import Any, Dict

import yaml


# Patrón para localizar referencias ${VAR} dentro de cadenas del YAML
_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    """Sustituye recursivamente ${VAR} por el valor de la variable de entorno.

    Si la variable no existe se deja la referencia intacta para que el fallo
    se detecte más adelante con un mensaje claro en get_env_or_config.
    """
    if isinstance(value, str):
        return _VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load(config_path: str) -> Dict[str, Any]:
    """Carga y valida el fichero YAML de configuración de VaultBlind.

    Verifica que existan las secciones obligatorias 'hosts', 'ldap' y 'vault'
    y expande las variables de entorno referenciadas con ${VAR}.
    """
    if not os.path.isfile(config_path):
        raise ValueError(f"No se encuentra el fichero de configuración: {config_path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"YAML inválido en {config_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"El fichero {config_path} debe contener un mapeo YAML en la raíz")

    for section in ("hosts", "ldap", "vault"):
        if section not in data:
            raise ValueError(
                f"Falta la sección obligatoria '{section}' en la configuración {config_path}"
            )

    return _expand_env(data)


def get_env_or_config(config_dict: Dict[str, Any], key: str, env_var: str) -> str:
    """Devuelve el valor de la variable de entorno si existe; si no, el del config.

    Lanza EnvironmentError si no hay valor disponible en ninguna de las dos fuentes.
    """
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value

    cfg_value = config_dict.get(key)
    if isinstance(cfg_value, str) and cfg_value and not _VAR_PATTERN.search(cfg_value):
        return cfg_value

    raise EnvironmentError(
        f"No se ha definido '{key}' en la configuración ni la variable de entorno '{env_var}'"
    )
