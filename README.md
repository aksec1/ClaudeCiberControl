# ClaudeCiberControl - Security Scanner Suite

Web Scanner + Nmap Potenciado + Vulnerability Analysis  
Frameworks: **MITRE ATT&CK** | **NIST SP 800-115** | **CIS Controls v8**

## Instalacion rapida (VM On-Premise)

```bash
git clone https://github.com/aksec1/ClaudeCiberControl.git
cd ClaudeCiberControl
sudo ./install.sh
source .venv/bin/activate
python3 main.py --demo
```

## Uso

```bash
./run.sh 192.168.1.1
./run.sh example.com --profile full
./run.sh https://mi-sitio.empresa.com --profile vuln
./run.sh --list-profiles
```

## Perfiles de escaneo

| Perfil | Descripcion |
|--------|-------------|
| fast | Top 100 puertos, rapido |
| default | Balanceado con deteccion de versiones |
| full | Todos los puertos + OS detection |
| vuln | Scripts NSE de vulnerabilidades |
| stealth | SYN scan sigiloso (-T2) |
| udp | UDP top 200 puertos |
| comprehensive | Full + scripts vuln/exploit |

## Docker

```bash
docker compose build
docker compose run cibercontrol 192.168.1.1 --profile default
```

## Reportes generados

- `output/reports/report_technical_*.html` - Reporte tecnico completo
- `output/reports/report_corporate_*.html` - Reporte ejecutivo
- `output/reports/report_*.json` - Datos en JSON
- `output/reports/report_*.txt` - Texto plano
