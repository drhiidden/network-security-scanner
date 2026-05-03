# AGENTS.md — network-security-scanner

---

## Identidad

| Campo | Valor |
|---|---|
| Nombre | **network-security-scanner** |
| Repo GitHub | `drhiidden/network-security-scanner` |
| Tagline | *Know your attack surface.* |
| Licencia | MIT |
| Estado | OSS público, proyecto académico |

**Propósito**: Herramienta educativa para aprender técnicas de red team y escaneo de red. Desarrollada en contexto académico de Seguridad Informática.

**ADVERTENCIA ÉTICA**: Solo usar en redes propias o con autorización explícita. El uso no autorizado es ilegal.

---

## Stack

| Capa | Tecnología |
|---|---|
| Lenguaje | Python 3.x |
| Scanning | scapy / nmap Python bindings |
| Reports | HTML |
| CLI | argparse |

---

## Reglas críticas

1. **Nunca añadir funcionalidades ofensivas activas** (exploits, payloads) — solo detección/scanning
2. **Advertencia ética visible** en README y en output del CLI
3. **El scope es educativo** — no convertir en herramienta de pen-testing profesional sin revisión legal
4. **Tests solo sobre localhost o redes de laboratorio** en CI

---

## Metodología

Desarrollado con [HCP (Human-Code-AI Protocol)](https://github.com/haletheia/human-code-ai-protocol).
