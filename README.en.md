![banner](docs/banner.png)

## Architecture

![architecture](docs/architecture.png)

## Demo

![demo](docs/demo.png)

> 🇪🇸 Read this in [Spanish](README.md).

# VaultBlind

VaultBlind detects privileged accounts on Linux and Active Directory that are not managed in your CyberArk vault. It helps you identify unmanaged privileged accounts and reduce the attack surface.

## Ethical Warning

**Use VaultBlind only on systems you own or have explicit permission to audit.** Unauthorized scanning is illegal and unethical. The authors assume no liability for misuse.

## Features

- Discovers privileged accounts on Linux via SSH (root, sudoers, system UIDs with valid shell).
- Discovers privileged accounts in Active Directory via LDAP (AdminCount=1, sensitive groups).
- Compares discovered accounts against CyberArk PVWA REST API.
- Reports gaps in terminal (Rich table), JSON, or CSV.
- Configuration via YAML with environment variable secrets.
- Includes a mock PVWA server for testing without real credentials.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourorg/vaultblind.git
   cd vaultblind
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copy the example configuration and adjust it:
   ```bash
   cp config/lab.yaml.example config/lab.yaml
   ```
4. Set environment variables for secrets (see Configuration).

## Usage

Run a scan:

```bash
python src/main.py scan --mode linux --config config/lab.yaml --output table
```

Modes: `linux`, `ad`, `both`. Output formats: `table`, `json`, `csv`.

Example output (table):

```
Privileged Accounts Not in Vault
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Username           ┃ Host/Domain     ┃ Source          ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ root               │ server1         │ Linux (SSH)     │
│ admin              │ corp.local      │ Active Directory│
└────────────────────┴─────────────────┴─────────────────┘
```

## Configuration

Configuration is loaded from a YAML file. Secrets are read from environment variables via `python-dotenv`. Example `config/lab.yaml`:

```yaml
linux:
  hosts:
    - hostname: server1
      username: scanuser
      key_file: ~/.ssh/id_rsa
  sudoers_path: /etc/sudoers

ad:
  server: ldap://dc.corp.local
  base_dn: dc=corp,dc=local
  bind_dn: cn=scanuser,cn=Users,dc=corp,dc=local

pvwa:
  url: https://pvwa.corp.local
  api_version: 10.10

mock_pvwa:
  enabled: false
  port: 8000
```

Environment variables:

- `VAULTBLIND_SSH_PASSWORD` (if not using key)
- `VAULTBLIND_AD_PASSWORD`
- `VAULTBLIND_PVWA_USERNAME`
- `VAULTBLIND_PVWA_PASSWORD`

## Modules

- `src/main.py`: CLI entry point (Typer).
- `src/scanner_ssh.py`: SSH scanner using Paramiko.
- `src/scanner_ldap.py`: LDAP scanner using ldap3.
- `src/models.py`: `AccountRecord` data model.
- `src/vault_client.py`: CyberArk PVWA API client.
- `src/gap_analyzer.py`: Set difference logic.
- `src/report_engine.py`: Output formatting (Rich, JSON, CSV).
- `src/config_loader.py`: YAML configuration loader.
- `src/mock_pvwa.py`: Mock PVWA server (FastAPI/uvicorn).

## Testing

Run the test suite:

```bash
pytest tests/
```

To use the mock PVWA server, set `mock_pvwa.enabled: true` in the config and run:

```bash
uvicorn src.mock_pvwa:app --port 8000
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

Javier Garrido Ortiz

## Contributing

Contributions are welcome. Please open an issue or pull request.

## Disclaimer

VaultBlind is provided "as is" without warranty of any kind. Use at your own risk. Always comply with applicable laws and regulations.