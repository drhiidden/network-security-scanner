#!/usr/bin/env python3
"""
Network Security Scanner - Main Application
Aplicación Principal del Escáner de Seguridad de Red

Esta es la aplicación principal que integra todos los módulos del escáner
de red siguiendo estándares de la industria y mejores prácticas de ingeniería.

Autor: [Tu Nombre]
Universidad: [Nombre de tu Universidad]
Curso: Seguridad Informática / Red Team
Fecha: 2025
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List, Optional

# Importar módulos del proyecto
try:
    from src.core.network_scanner import NetworkScanner, ScanConfiguration, quick_scan
    from src.core.vulnerability_analyzer import VulnerabilityAnalyzer, analyze_host_vulnerabilities
    from src.utils.report_generator import ReportGenerator
    from src.utils.config_manager import ConfigManager
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("💡 Make sure you're running from the project root directory")
    sys.exit(1)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class NetworkSecurityScanner:
    """
    Clase principal de la aplicación
    
    Coordina todos los componentes del escáner de red y proporciona
    una interfaz unificada para el usuario.
    """
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.report_generator = ReportGenerator()
        self.network_scanner = None
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        
    def run_discovery_scan(self, target: str, **kwargs) -> List:
        """
        Ejecuta escaneo de descubrimiento de hosts
        
        Args:
            target: IP o rango de red objetivo
            **kwargs: Argumentos adicionales
            
        Returns:
            Lista de hosts descubiertos
        """
        logger.info(f"Starting discovery scan for {target}")
        
        config = ScanConfiguration(
            target=target,
            **kwargs
        )
        
        self.network_scanner = NetworkScanner(config)
        results = self.network_scanner.run_scan(discovery_only=True)
        
        logger.info(f"Discovery scan completed. Found {len(results)} hosts")
        return results
    
    def run_full_scan(self, target: str, ports: Optional[List[int]] = None, **kwargs) -> List:
        """
        Ejecuta escaneo completo de red
        
        Args:
            target: IP o rango de red objetivo
            ports: Lista de puertos a escanear
            **kwargs: Argumentos adicionales
            
        Returns:
            Lista de resultados de escaneo
        """
        logger.info(f"Starting full scan for {target}")
        
        config = ScanConfiguration(
            target=target,
            ports=ports or [],
            **kwargs
        )
        
        self.network_scanner = NetworkScanner(config)
        results = self.network_scanner.run_scan()
        
        logger.info(f"Full scan completed. Found {len(results)} hosts")
        return results
    
    def run_vulnerability_analysis(self, host: str, ports: List[int]) -> List:
        """
        Ejecuta análisis de vulnerabilidades
        
        Args:
            host: IP del host a analizar
            ports: Lista de puertos a verificar
            
        Returns:
            Lista de resultados de análisis de vulnerabilidades
        """
        logger.info(f"Starting vulnerability analysis for {host}")
        
        results = self.vulnerability_analyzer.analyze_host(host, ports)
        
        logger.info(f"Vulnerability analysis completed for {host}")
        return results
    
    def generate_report(self, results: List, report_type: str = "html", **kwargs):
        """
        Genera reporte de los resultados
        
        Args:
            results: Resultados del escaneo
            report_type: Tipo de reporte (html, json, pdf)
            **kwargs: Argumentos adicionales
        """
        logger.info(f"Generating {report_type} report")
        
        if report_type == "html":
            self.report_generator.generate_html_report(results, **kwargs)
        elif report_type == "json":
            self.report_generator.generate_json_report(results, **kwargs)
        else:
            logger.warning(f"Unsupported report type: {report_type}")
    
    def run_comprehensive_scan(self, target: str, ports: Optional[List[int]] = None, 
                             generate_report: bool = True, **kwargs):
        """
        Ejecuta escaneo completo con análisis de vulnerabilidades
        
        Args:
            target: IP o rango de red objetivo
            ports: Lista de puertos a escanear
            generate_report: Si generar reporte automáticamente
            **kwargs: Argumentos adicionales
        """
        logger.info(f"Starting comprehensive scan for {target}")
        
        # Paso 1: Descubrimiento de hosts
        print("🔍 Step 1: Host Discovery")
        hosts = self.run_discovery_scan(target, **kwargs)
        
        if not hosts:
            print("❌ No hosts found. Exiting.")
            return
        
        # Paso 2: Escaneo de puertos
        print("🔍 Step 2: Port Scanning")
        scan_results = self.run_full_scan(target, ports, **kwargs)
        
        # Paso 3: Análisis de vulnerabilidades
        print("⚠️ Step 3: Vulnerability Analysis")
        vuln_results = []
        
        for host_result in scan_results:
            if host_result.open_ports:
                open_ports = [port['port'] for port in host_result.open_ports]
                vuln_result = self.run_vulnerability_analysis(host_result.host_ip, open_ports)
                vuln_results.extend(vuln_result)
        
        # Paso 4: Generar reporte
        if generate_report:
            print("📄 Step 4: Generating Report")
            self.generate_report({
                'hosts': scan_results,
                'vulnerabilities': vuln_results
            })
        
        print("✅ Comprehensive scan completed!")


def create_parser() -> argparse.ArgumentParser:
    """
    Crea el parser de argumentos de línea de comandos
    
    Returns:
        Parser configurado
    """
    parser = argparse.ArgumentParser(
        description="🔍 Network Security Scanner - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️ ETHICAL WARNING: Only use on networks you own or have explicit authorization.

Examples:
  # Discovery scan
  python main.py --target 192.168.1.0/24 --discovery
  
  # Full scan with specific ports
  python main.py --target 192.168.1.1 --ports 80,443,22,21
  
  # Comprehensive scan with vulnerability analysis
  python main.py --target 192.168.1.0/24 --comprehensive --report
  
  # Quick scan
  python main.py --target 192.168.1.1 --quick
        """
    )
    
    # Argumentos principales
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target IP or network range (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--ports', '-p',
        help='Specific ports to scan (comma-separated)'
    )
    
    # Modos de escaneo
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument(
        '--discovery',
        action='store_true',
        help='Only perform host discovery'
    )
    
    scan_group.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan with default settings'
    )
    
    scan_group.add_argument(
        '--comprehensive',
        action='store_true',
        help='Comprehensive scan with vulnerability analysis'
    )
    
    # Configuración de escaneo
    parser.add_argument(
        '--timeout',
        type=int,
        default=3,
        help='Connection timeout in seconds (default: 3)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Maximum number of threads (default: 100)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Reportes
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate report automatically'
    )
    
    parser.add_argument(
        '--report-type',
        choices=['html', 'json', 'pdf'],
        default='html',
        help='Report type (default: html)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    
    return parser


def parse_ports(ports_str: str) -> List[int]:
    """
    Parsea string de puertos a lista de enteros
    
    Args:
        ports_str: String con puertos separados por coma
        
    Returns:
        Lista de puertos
    """
    if not ports_str:
        return []
    
    try:
        return [int(p.strip()) for p in ports_str.split(',')]
    except ValueError as e:
        logger.error(f"Invalid port format: {e}")
        sys.exit(1)


def setup_environment():
    """
    Configura el entorno de la aplicación
    """
    # Crear directorios necesarios
    directories = ['logs', 'reports', 'config']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Configurar logging
    if not Path('logs').exists():
        Path('logs').mkdir(exist_ok=True)


def main():
    """
    Función principal de la aplicación
    """
    # Configurar entorno
    setup_environment()
    
    # Crear parser y parsear argumentos
    parser = create_parser()
    args = parser.parse_args()
    
    # Configurar logging según verbosidad
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Crear instancia del escáner
    scanner = NetworkSecurityScanner()
    
    try:
        # Parsear puertos si se especificaron
        ports = parse_ports(args.ports) if args.ports else None
        
        # Ejecutar según el modo seleccionado
        if args.discovery:
            # Modo solo descubrimiento
            results = scanner.run_discovery_scan(
                args.target,
                timeout=args.timeout,
                max_threads=args.threads
            )
            
        elif args.quick:
            # Modo escaneo rápido
            results = quick_scan(args.target, ports)
            
        elif args.comprehensive:
            # Modo escaneo completo
            scanner.run_comprehensive_scan(
                args.target,
                ports=ports,
                generate_report=args.report,
                timeout=args.timeout,
                max_threads=args.threads
            )
            
        else:
            # Modo por defecto (escaneo completo)
            results = scanner.run_full_scan(
                args.target,
                ports=ports,
                timeout=args.timeout,
                max_threads=args.threads
            )
            
            # Generar reporte si se solicita
            if args.report:
                scanner.generate_report(results, args.report_type)
        
        print("✅ Scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
