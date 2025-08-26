#!/usr/bin/env python3
"""
Reconnaissance Module - Core Component
Módulo de Reconocimiento - Componente Principal

Este módulo implementa técnicas de reconocimiento pasivo y activo
siguiendo estándares de la industria y mejores prácticas de seguridad.

Clases principales:
- ReconnaissanceEngine: Motor principal de reconocimiento
- PassiveReconnaissance: Reconocimiento pasivo
- ActiveReconnaissance: Reconocimiento activo

Autor: [Tu Nombre]
Universidad: [Nombre de tu Universidad]
Curso: Seguridad Informática
"""

import socket
import requests
import dns.resolver
import whois
import subprocess
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging
from datetime import datetime

# Importaciones de terceros
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    logging.error(f"Error importing required libraries: {e}")
    raise

# Configuración de logging
logger = logging.getLogger(__name__)


@dataclass
class ReconnaissanceResult:
    """
    Data class para resultados de reconocimiento
    
    Attributes:
        target: Objetivo del reconocimiento
        reconnaissance_type: Tipo de reconocimiento
        data: Datos obtenidos
        timestamp: Timestamp del reconocimiento
        duration: Duración del reconocimiento
    """
    target: str
    reconnaissance_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    duration: float = 0.0


class BaseReconnaissance(ABC):
    """
    Clase base abstracta para técnicas de reconocimiento
    
    Define la interfaz común que deben implementar todas las técnicas
    de reconocimiento siguiendo el patrón Strategy.
    """
    
    def __init__(self):
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def gather_info(self, target: str, **kwargs) -> ReconnaissanceResult:
        """Método abstracto que debe implementar cada técnica"""
        pass
    
    def log_reconnaissance_start(self, target: str):
        """Registra el inicio del reconocimiento"""
        self.logger.info(f"Starting {self.__class__.__name__} for {target}")
    
    def log_reconnaissance_complete(self, result: ReconnaissanceResult):
        """Registra la finalización del reconocimiento"""
        self.logger.info(f"{self.__class__.__name__} completed for {result.target}")


class PassiveReconnaissance(BaseReconnaissance):
    """
    Reconocimiento pasivo
    
    Implementa técnicas de reconocimiento que no interactúan directamente
    con el objetivo, como WHOIS, DNS, etc.
    """
    
    def gather_info(self, target: str, **kwargs) -> ReconnaissanceResult:
        """Recopila información pasiva del objetivo"""
        self.log_reconnaissance_start(target)
        start_time = datetime.now()
        
        result = ReconnaissanceResult(
            target=target,
            reconnaissance_type="Passive"
        )
        
        try:
            # WHOIS information
            whois_info = self._get_whois_info(target)
            result.data['whois'] = whois_info
            
            # DNS information
            dns_info = self._get_dns_info(target)
            result.data['dns'] = dns_info
            
            # Subdomain enumeration
            subdomains = self._enumerate_subdomains(target)
            result.data['subdomains'] = subdomains
            
            # IP geolocation
            geo_info = self._get_geolocation(target)
            result.data['geolocation'] = geo_info
            
        except Exception as e:
            self.logger.error(f"Passive reconnaissance failed: {e}")
            result.data['error'] = str(e)
        
        result.duration = (datetime.now() - start_time).total_seconds()
        self.log_reconnaissance_complete(result)
        return result
    
    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Obtiene información WHOIS del dominio"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status
            }
        except Exception as e:
            self.logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}
    
    def _get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Obtiene información DNS del dominio"""
        dns_info = {}
        
        try:
            # A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(record) for record in a_records]
            except:
                dns_info['a_records'] = []
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(record.exchange) for record in mx_records]
            except:
                dns_info['mx_records'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(record) for record in ns_records]
            except:
                dns_info['ns_records'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(record) for record in txt_records]
            except:
                dns_info['txt_records'] = []
                
        except Exception as e:
            self.logger.debug(f"DNS lookup failed for {domain}: {e}")
            dns_info['error'] = str(e)
        
        return dns_info
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumera subdominios del dominio"""
        subdomains = []
        
        # Lista de subdominios comunes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'api', 'cdn', 'static', 'img', 'images', 'media',
            'support', 'help', 'docs', 'wiki', 'forum', 'shop'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except:
                continue
        
        return subdomains
    
    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Obtiene información de geolocalización de la IP"""
        try:
            # Usar servicio gratuito de geolocalización
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org')
                }
        except Exception as e:
            self.logger.debug(f"Geolocation lookup failed for {ip}: {e}")
        
        return {'error': 'Unable to get geolocation'}


class ActiveReconnaissance(BaseReconnaissance):
    """
    Reconocimiento activo
    
    Implementa técnicas de reconocimiento que interactúan directamente
    con el objetivo, como banner grabbing, etc.
    """
    
    def gather_info(self, target: str, **kwargs) -> ReconnaissanceResult:
        """Recopila información activa del objetivo"""
        self.log_reconnaissance_start(target)
        start_time = datetime.now()
        
        result = ReconnaissanceResult(
            target=target,
            reconnaissance_type="Active"
        )
        
        try:
            # Banner grabbing
            banners = self._grab_banners(target, kwargs.get('ports', [80, 443, 22, 21]))
            result.data['banners'] = banners
            
            # Service enumeration
            services = self._enumerate_services(target, kwargs.get('ports', []))
            result.data['services'] = services
            
            # Technology detection
            technologies = self._detect_technologies(target)
            result.data['technologies'] = technologies
            
        except Exception as e:
            self.logger.error(f"Active reconnaissance failed: {e}")
            result.data['error'] = str(e)
        
        result.duration = (datetime.now() - start_time).total_seconds()
        self.log_reconnaissance_complete(result)
        return result
    
    def _grab_banners(self, target: str, ports: List[int]) -> Dict[int, str]:
        """Obtiene banners de los servicios"""
        banners = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                
                # Enviar request básico
                if port == 80:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                elif port == 443:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                else:
                    sock.send(b"\r\n")
                
                # Recibir respuesta
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                banners[port] = response.strip()
                sock.close()
                
            except Exception as e:
                self.logger.debug(f"Banner grabbing failed for {target}:{port}: {e}")
                continue
        
        return banners
    
    def _enumerate_services(self, target: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Enumera servicios en los puertos especificados"""
        services = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service_name = self._get_service_name(port)
                    services[port] = {
                        'name': service_name,
                        'state': 'open',
                        'protocol': 'TCP'
                    }
                    
            except Exception as e:
                self.logger.debug(f"Service enumeration failed for {target}:{port}: {e}")
                continue
        
        return services
    
    def _detect_technologies(self, target: str) -> Dict[str, Any]:
        """Detecta tecnologías utilizadas"""
        technologies = {}
        
        try:
            # Detectar servidor web
            response = requests.get(f"http://{target}", timeout=5, allow_redirects=False)
            if response.status_code == 200:
                server = response.headers.get('Server', 'Unknown')
                technologies['web_server'] = server
                
                # Detectar tecnologías basadas en headers
                if 'X-Powered-By' in response.headers:
                    technologies['powered_by'] = response.headers['X-Powered-By']
                
                # Detectar tecnologías basadas en contenido
                content = response.text.lower()
                if 'wordpress' in content:
                    technologies['cms'] = 'WordPress'
                elif 'drupal' in content:
                    technologies['cms'] = 'Drupal'
                elif 'joomla' in content:
                    technologies['cms'] = 'Joomla'
                    
        except Exception as e:
            self.logger.debug(f"Technology detection failed for {target}: {e}")
        
        return technologies
    
    def _get_service_name(self, port: int) -> str:
        """Obtiene el nombre del servicio basado en el puerto"""
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 139: 'SMB', 445: 'SMB',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return service_map.get(port, 'Unknown')


class ReconnaissanceEngine:
    """
    Motor principal de reconocimiento
    
    Esta clase coordina todas las técnicas de reconocimiento y proporciona
    una interfaz unificada para realizar reconocimientos completos.
    
    Ejemplo de uso:
        engine = ReconnaissanceEngine()
        results = engine.run_reconnaissance("example.com")
    """
    
    def __init__(self):
        self.console = Console()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Inicializar técnicas de reconocimiento
        self.passive_recon = PassiveReconnaissance()
        self.active_recon = ActiveReconnaissance()
        
    def run_reconnaissance(self, target: str, reconnaissance_type: str = "both", **kwargs) -> Dict[str, ReconnaissanceResult]:
        """
        Ejecuta reconocimiento completo del objetivo
        
        Args:
            target: Objetivo del reconocimiento
            reconnaissance_type: Tipo de reconocimiento (passive, active, both)
            **kwargs: Argumentos adicionales
            
        Returns:
            Diccionario con resultados de reconocimiento
        """
        self.logger.info(f"Starting reconnaissance for {target}")
        
        results = {}
        
        if reconnaissance_type in ["passive", "both"]:
            self.console.print("🔍 Running passive reconnaissance...", style="bold green")
            passive_result = self.passive_recon.gather_info(target, **kwargs)
            results['passive'] = passive_result
        
        if reconnaissance_type in ["active", "both"]:
            self.console.print("🔍 Running active reconnaissance...", style="bold green")
            active_result = self.active_recon.gather_info(target, **kwargs)
            results['active'] = active_result
        
        self._print_reconnaissance_summary(target, results)
        return results
    
    def _print_reconnaissance_summary(self, target: str, results: Dict[str, ReconnaissanceResult]):
        """Imprime el resumen del reconocimiento"""
        self.console.print(f"\n📊 RECONNAISSANCE SUMMARY - {target}", style="bold blue")
        
        for recon_type, result in results.items():
            self.console.print(f"\n{recon_type.upper()} RECONNAISSANCE:")
            self.console.print(f"Duration: {result.duration:.2f} seconds")
            
            if 'error' in result.data:
                self.console.print(f"❌ Error: {result.data['error']}", style="bold red")
            else:
                self._display_reconnaissance_data(result.data)
    
    def _display_reconnaissance_data(self, data: Dict[str, Any]):
        """Muestra los datos de reconocimiento"""
        if 'whois' in data and data['whois']:
            self.console.print("📋 WHOIS Information:")
            whois_info = data['whois']
            for key, value in whois_info.items():
                if key != 'error':
                    self.console.print(f"  {key}: {value}")
        
        if 'dns' in data and data['dns']:
            self.console.print("🌐 DNS Information:")
            dns_info = data['dns']
            for record_type, records in dns_info.items():
                if record_type != 'error' and records:
                    self.console.print(f"  {record_type.upper()}: {', '.join(records)}")
        
        if 'subdomains' in data and data['subdomains']:
            self.console.print(f"🔗 Subdomains found: {len(data['subdomains'])}")
            for subdomain in data['subdomains'][:5]:  # Mostrar solo los primeros 5
                self.console.print(f"  - {subdomain}")


# Funciones de utilidad
def run_passive_reconnaissance(target: str, **kwargs) -> ReconnaissanceResult:
    """
    Función de utilidad para reconocimiento pasivo
    
    Args:
        target: Objetivo del reconocimiento
        **kwargs: Argumentos adicionales
        
    Returns:
        Resultado del reconocimiento pasivo
    """
    recon = PassiveReconnaissance()
    return recon.gather_info(target, **kwargs)


def run_active_reconnaissance(target: str, **kwargs) -> ReconnaissanceResult:
    """
    Función de utilidad para reconocimiento activo
    
    Args:
        target: Objetivo del reconocimiento
        **kwargs: Argumentos adicionales
        
    Returns:
        Resultado del reconocimiento activo
    """
    recon = ActiveReconnaissance()
    return recon.gather_info(target, **kwargs)
