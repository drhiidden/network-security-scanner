#!/usr/bin/env python3
"""
Report Generator Module
Módulo Generador de Reportes

Este módulo maneja la generación de reportes en diferentes formatos
siguiendo estándares de la industria.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generador de reportes
    
    Maneja la generación de reportes en diferentes formatos:
    - HTML: Reportes visuales y profesionales
    - JSON: Para integración con otras herramientas
    - PDF: (Próximamente)
    """
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def generate_html_report(self, results: Dict[str, Any], **kwargs) -> str:
        """
        Genera reporte HTML
        
        Args:
            results: Resultados del escaneo
            **kwargs: Argumentos adicionales
            
        Returns:
            Ruta del archivo HTML generado
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.html"
        filepath = self.output_dir / filename
        
        html_content = self._create_html_content(results, **kwargs)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    def generate_json_report(self, results: Dict[str, Any], **kwargs) -> str:
        """
        Genera reporte JSON
        
        Args:
            results: Resultados del escaneo
            **kwargs: Argumentos adicionales
            
        Returns:
            Ruta del archivo JSON generado
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.json"
        filepath = self.output_dir / filename
        
        # Preparar datos para JSON
        json_data = {
            'report_info': {
                'generated_at': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'report_type': 'network_security_scan'
            },
            'scan_results': results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    def _create_html_content(self, results: Dict[str, Any], **kwargs) -> str:
        """Crea el contenido HTML del reporte"""
        
        # Extraer datos de los resultados
        hosts = results.get('hosts', [])
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Contar estadísticas
        total_hosts = len(hosts)
        total_vulnerabilities = len(vulnerabilities)
        open_ports = sum(len(host.get('open_ports', [])) for host in hosts)
        
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007bff;
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            color: #666;
            margin: 10px 0 0 0;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .summary h2 {{
            color: #333;
            margin-top: 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .stat-card {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }}
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        .vulnerability-high {{
            color: #dc3545;
            font-weight: bold;
        }}
        .vulnerability-medium {{
            color: #ffc107;
            font-weight: bold;
        }}
        .vulnerability-low {{
            color: #28a745;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Security Scan Report</h1>
            <p>Herramienta Educativa para Ingeniería Informática</p>
            <p>Generado el: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Resumen Ejecutivo</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_hosts}</div>
                    <div class="stat-label">Hosts Escaneados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{open_ports}</div>
                    <div class="stat-label">Puertos Abiertos</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_vulnerabilities}</div>
                    <div class="stat-label">Vulnerabilidades</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🖥️ Hosts Descubiertos</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>Puertos Abiertos</th>
                        <th>Servicios</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Agregar información de hosts
        for host in hosts:
            host_ip = host.get('host_ip', 'Unknown')
            hostname = host.get('hostname', 'Unknown')
            open_ports = host.get('open_ports', [])
            
            ports_str = ', '.join([f"{port['port']}" for port in open_ports])
            services_str = ', '.join([f"{port['service']}" for port in open_ports])
            
            html += f"""
                    <tr>
                        <td>{host_ip}</td>
                        <td>{hostname}</td>
                        <td>{ports_str}</td>
                        <td>{services_str}</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        </div>
        """
        
        # Agregar sección de vulnerabilidades si existen
        if vulnerabilities:
            html += """
        <div class="section">
            <h2>⚠️ Vulnerabilidades Detectadas</h2>
            <table>
                <thead>
                    <tr>
                        <th>Servicio</th>
                        <th>Tipo</th>
                        <th>Severidad</th>
                        <th>Descripción</th>
                        <th>Recomendación</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for vuln in vulnerabilities:
                severity_class = f"vulnerability-{vuln.get('severity', 'low').lower()}"
                html += f"""
                    <tr>
                        <td>{vuln.get('check_name', 'Unknown')}</td>
                        <td>{vuln.get('type', 'Unknown')}</td>
                        <td class="{severity_class}">{vuln.get('severity', 'Unknown')}</td>
                        <td>{vuln.get('description', 'No description')}</td>
                        <td>{vuln.get('recommendation', 'No recommendation')}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
        </div>
            """
        
        # Cerrar HTML
        html += f"""
        <div class="footer">
            <p>🔒 Este reporte fue generado por una herramienta educativa para propósitos de aprendizaje.</p>
            <p>⚠️ Solo use estas herramientas en redes que posea o tenga autorización explícita.</p>
            <p>📧 Para más información: [tu.email@universidad.edu]</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
