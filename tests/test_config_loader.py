import os

import pytest
import yaml

from src.config_loader import ConfigLoader


# YAML mínimo válido para los tests
YAML_VALIDO = {
    "hosts": [{"name": "srv01", "address": "10.0.0.5", "user": "auditor"}],
    "ldap": {"server": "ldap://dc01.lab.local", "base_dn": "DC=lab,DC=local"},
    "vault": {"pvwa_url": "https://pvwa.lab.local", "account": "svc_vaultblind"},
}


def _escribir_yaml(tmp_path, datos):
    ruta = tmp_path / "config.yaml"
    ruta.write_text(yaml.safe_dump(datos), encoding="utf-8")
    return str(ruta)


def test_load_yaml_valido(tmp_path):
    ruta = _escribir_yaml(tmp_path, YAML_VALIDO)
    config = ConfigLoader(ruta).load()
    assert "hosts" in config
    assert "ldap" in config
    assert "vault" in config
    assert config["vault"]["pvwa_url"] == "https://pvwa.lab.local"


def test_load_sin_seccion_vault_lanza_valueerror(tmp_path):
    datos = {k: v for k, v in YAML_VALIDO.items() if k != "vault"}
    ruta = _escribir_yaml(tmp_path, datos)
    with pytest.raises(ValueError) as excinfo:
        ConfigLoader(ruta).load()
    assert "vault" in str(excinfo.value).lower()


def test_load_expande_variable_de_entorno(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_VAR", "valor-expandido")
    datos = dict(YAML_VALIDO)
    datos["vault"] = {"pvwa_url": "${TEST_VAR}", "account": "svc_vaultblind"}
    ruta = _escribir_yaml(tmp_path, datos)
    config = ConfigLoader(ruta).load()
    assert config["vault"]["pvwa_url"] == "valor-expandido"


def test_get_env_or_config_prioriza_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTBLIND_PVWA_URL", "https://env.lab.local")
    ruta = _escribir_yaml(tmp_path, YAML_VALIDO)
    loader = ConfigLoader(ruta)
    loader.load()
    valor = loader.get_env_or_config("VAULTBLIND_PVWA_URL", "vault.pvwa_url")
    assert valor == "https://env.lab.local"


def test_get_env_or_config_sin_valor_lanza_environmenterror(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULTBLIND_INEXISTENTE", raising=False)
    datos = dict(YAML_VALIDO)
    datos["vault"] = {"account": "svc_vaultblind"}
    ruta = _escribir_yaml(tmp_path, datos)
    loader = ConfigLoader(ruta)
    loader.load()
    with pytest.raises(EnvironmentError):
        loader.get_env_or_config("VAULTBLIND_INEXISTENTE", "vault.pvwa_url")
