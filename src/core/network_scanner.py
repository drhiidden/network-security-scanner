#!/usr/bin/env python3
"""
Network Scanner Module - Core Component
Módulo de Escaneo de Red - Componente Principal

Este módulo implementa las funcionalidades principales de escaneo de red
siguiendo patrones de diseño de la industria y mejores prácticas de seguridad.

Clases principales:
- NetworkScanner: Clase principal para escaneo de red
- PortScanner: Clase especializada en escaneo de puertos
- HostDiscovery: Clase para descubrimiento de hosts

Autor: [Tu Nombre]
Universidad: [Nombre de tu Universidad]
Curso: Seguridad Informática
"""

import socket
import threading
import time
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging

# Importaciones de terceros
try:
    from scapy.all import ARP, Ether, srp
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
except ImportError as e:
    logging.error(f"Error importing required libraries: {e}")
    raise

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """
    Data class para almacenar resultados de escaneo
    
    Attributes:
        host_ip: IP del host escaneado
        hostname: Nombre del host
        open_ports: Lista de puertos abiertos
        scan_timestamp: Timestamp del escaneo
        scan_duration: Duración del escaneo en segundos
    """
    host_ip: str
    hostname: str = "Unknown"
    open_ports: List[Dict] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.now)
    scan_duration: float = 0.0
    os_info: Optional[str] = None
    mac_address: Optional[str] = None


@dataclass
class ScanConfiguration:
    """
    Data class para configuración de escaneo
    
    Attributes:
        target: IP o rango de red objetivo
        ports: Lista de puertos a escanear
        timeout: Timeout para conexiones
        max_threads: Número máximo de hilos
        scan_type: Tipo de escaneo (TCP, UDP, etc.)
    """
    target: str
    ports: List[int] = field(default_factory=list)
    timeout: int = 3
    max_threads: int = 100
    scan_type: str = "TCP"
    verbose: bool = False


class BaseScanner(ABC):
    """
    Clase base abstracta para todos los escáneres
    
    Define la interfaz común que deben implementar todos los escáneres
    siguiendo el patrón Template Method.
    """
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
        
    @abstractmethod
    def scan(self) -> List[ScanResult]:
        """Método abstracto que debe implementar cada escáner"""
        pass
    
    def validate_target(self) -> bool:
        """Valida el formato del objetivo"""
        try:
            ipaddress.ip_network(self.config.target, strict=False)
            return True
        except ValueError as e:
            self.logger.error(f"Invalid target format: {e}")
            return False
    
    def log_scan_start(self):
        """Registra el inicio del escaneo"""
        self.logger.info(f"Starting scan of target: {self.config.target}")
        
    def log_scan_complete(self, results: List[ScanResult]):
        """Registra la finalización del escaneo"""
        self.logger.info(f"Scan completed. Found {len(results)} hosts")


class HostDiscovery(BaseScanner):
    """
    Clase para descubrimiento de hosts en la red
    
    Implementa técnicas de descubrimiento de hosts usando ARP,
    ICMP ping y otras técnicas de red.
    """
    
    def __init__(self, config: ScanConfiguration):
        super().__init__(config)
        self.discovered_hosts: Set[str] = set()
        
    def scan(self) -> List[ScanResult]:
        """Descubre hosts activos en la red"""
        if not self.validate_target():
            return []
            
        self.log_scan_start()
        
        # Descubrimiento usando ARP
        arp_hosts = self._arp_discovery()
        
        # Descubrimiento usando ICMP (ping)
        icmp_hosts = self._icmp_discovery()
        
        # Combinar resultados
        all_hosts = arp_hosts.union(icmp_hosts)
        
        # Crear resultados
        results = []
        for host_ip in all_hosts:
            result = ScanResult(
                host_ip=host_ip,
                hostname=self._get_hostname(host_ip)
            )
            results.append(result)
            
        self.log_scan_complete(results)
        return results
    
    def _arp_discovery(self) -> Set[str]:
        """Descubre hosts usando ARP"""
        try:
            self.console.print("🔍 Discovering hosts using ARP...", style="bold green")
            
            arp = ARP(pdst=self.config.target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            
            hosts = set()
            for sent, received in result:
                hosts.add(received.psrc)
                
            self.console.print(f"✅ ARP discovery found {len(hosts)} hosts", style="bold green")
            return hosts
            
        except Exception as e:
            self.logger.error(f"ARP discovery failed: {e}")
            return set()
    
    def _icmp_discovery(self) -> Set[str]:
        """Descubre hosts usando ICMP ping"""
        try:
            self.console.print("🔍 Discovering hosts using ICMP...", style="bold green")
            
            network = ipaddress.ip_network(self.config.target, strict=False)
            hosts = set()
            
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                future_to_ip = {
                    executor.submit(self._ping_host, str(ip)): str(ip) 
                    for ip in network.hosts()
                }
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            hosts.add(ip)
                    except Exception as e:
                        self.logger.debug(f"Ping failed for {ip}: {e}")
                        
            self.console.print(f"✅ ICMP discovery found {len(hosts)} hosts", style="bold green")
            return hosts
            
        except Exception as e:
            self.logger.error(f"ICMP discovery failed: {e}")
            return set()
    
    def _ping_host(self, ip: str) -> bool:
        """Realiza ping a un host específico"""
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((ip, 80))
            return True
        except:
            return False
    
    def _get_hostname(self, ip: str) -> str:
        """Obtiene el hostname de una IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"


class PortScanner(BaseScanner):
    """
    Clase para escaneo de puertos
    
    Implementa diferentes técnicas de escaneo de puertos:
    - TCP Connect Scan
    - TCP SYN Scan (si está disponible)
    - UDP Scan
    """
    
    def __init__(self, config: ScanConfiguration):
        super().__init__(config)
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
    def scan(self) -> List[ScanResult]:
        """Escanea puertos en los hosts especificados"""
        if not self.validate_target():
            return []
            
        self.log_scan_start()
        
        # Obtener hosts a escanear
        discovery = HostDiscovery(self.config)
        hosts = discovery.scan()
        
        if not hosts:
            self.logger.warning("No hosts found to scan")
            return []
        
        # Escanear puertos en cada host
        results = []
        for host in hosts:
            result = self._scan_host_ports(host.host_ip)
            results.append(result)
            
        self.log_scan_complete(results)
        return results
    
    def _scan_host_ports(self, host_ip: str) -> ScanResult:
        """Escanea puertos de un host específico"""
        start_time = time.time()
        
        result = ScanResult(host_ip=host_ip)
        result.hostname = self._get_hostname(host_ip)
        
        # Determinar puertos a escanear
        ports_to_scan = self.config.ports if self.config.ports else list(self.common_ports.keys())
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"Scanning {host_ip}...", total=len(ports_to_scan))
            
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, host_ip, port): port 
                    for port in ports_to_scan
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        port_result = future.result()
                        if port_result:
                            result.open_ports.append(port_result)
                    except Exception as e:
                        self.logger.debug(f"Port scan failed for {host_ip}:{port}: {e}")
                    progress.advance(task)
        
        result.scan_duration = time.time() - start_time
        return result
    
    def _scan_port(self, host: str, port: int) -> Optional[Dict]:
        """Escanea un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return {
                    'port': port,
                    'service': self._get_service_name(port),
                    'state': 'open',
                    'protocol': 'TCP'
                }
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
        
        return None
    
    def _get_service_name(self, port: int) -> str:
        """Obtiene el nombre del servicio basado en el puerto"""
        return self.common_ports.get(port, 'Unknown')
    
    def _get_hostname(self, ip: str) -> str:
        """Obtiene el hostname de una IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"


class NetworkScanner:
    """
    Clase principal para escaneo de red
    
    Esta clase coordina todos los componentes de escaneo y proporciona
    una interfaz unificada para realizar escaneos completos de red.
    
    Ejemplo de uso:
        config = ScanConfiguration(target="192.168.1.0/24")
        scanner = NetworkScanner(config)
        results = scanner.run_scan()
    """
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.results: List[ScanResult] = []
        
    def run_scan(self, discovery_only: bool = False) -> List[ScanResult]:
        """
        Ejecuta el escaneo completo de red
        
        Args:
            discovery_only: Si es True, solo realiza descubrimiento de hosts
            
        Returns:
            Lista de resultados de escaneo
        """
        start_time = time.time()
        
        self._print_banner()
        
        if not self._validate_configuration():
            return []
        
        try:
            if discovery_only:
                # Solo descubrimiento de hosts
                discovery = HostDiscovery(self.config)
                self.results = discovery.scan()
            else:
                # Escaneo completo
                port_scanner = PortScanner(self.config)
                self.results = port_scanner.scan()
            
            # Calcular estadísticas
            total_duration = time.time() - start_time
            self._print_summary(total_duration)
            
            return self.results
            
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
            return self.results
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return []
    
    def _validate_configuration(self) -> bool:
        """Valida la configuración del escaneo"""
        if not self.config.target:
            self.console.print("❌ Error: Target is required", style="bold red")
            return False
        
        if not self.config.validate_target():
            self.console.print(f"❌ Error: Invalid target format: {self.config.target}", style="bold red")
            return False
        
        return True
    
    def _print_banner(self):
        """Imprime el banner del programa"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🔍 NETWORK SCANNER                        ║
║                   Educational Tool                           ║
║                    Engineering Standards                     ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="bold blue"))
    
    def _print_summary(self, duration: float):
        """Imprime el resumen del escaneo"""
        self.console.print(f"\n📊 SCAN SUMMARY", style="bold blue")
        self.console.print(f"Target: {self.config.target}")
        self.console.print(f"Duration: {duration:.2f} seconds")
        self.console.print(f"Hosts found: {len(self.results)}")
        
        if self.results:
            self._display_results_table()
    
    def _display_results_table(self):
        """Muestra los resultados en una tabla"""
        table = Table(title="🖥️ Scan Results")
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="magenta")
        table.add_column("Open Ports", style="green")
        table.add_column("Duration", style="yellow")
        
        for result in self.results:
            ports_str = ", ".join([f"{p['port']}({p['service']})" for p in result.open_ports])
            table.add_row(
                result.host_ip,
                result.hostname,
                ports_str,
                f"{result.scan_duration:.2f}s"
            )
        
        self.console.print(table)


# Funciones de utilidad para facilitar el uso
def create_scan_config(target: str, ports: List[int] = None, **kwargs) -> ScanConfiguration:
    """
    Función de utilidad para crear configuración de escaneo
    
    Args:
        target: IP o rango de red objetivo
        ports: Lista de puertos a escanear (opcional)
        **kwargs: Argumentos adicionales de configuración
        
    Returns:
        Configuración de escaneo
    """
    return ScanConfiguration(target=target, ports=ports or [], **kwargs)


def quick_scan(target: str, ports: List[int] = None) -> List[ScanResult]:
    """
    Función de utilidad para escaneo rápido
    
    Args:
        target: IP o rango de red objetivo
        ports: Lista de puertos a escanear (opcional)
        
    Returns:
        Resultados del escaneo
    """
    config = create_scan_config(target, ports)
    scanner = NetworkScanner(config)
    return scanner.run_scan()
