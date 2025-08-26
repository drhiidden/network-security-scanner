#!/usr/bin/env python3
"""
Configuration Manager Module
Módulo Gestor de Configuración

Este módulo maneja la configuración de la aplicación siguiendo
patrones de diseño de la industria.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuración del escáner"""
    default_ports: list = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443])
    connection_timeout: int = 3
    scan_timeout: int = 30
    max_threads: int = 100
    rate_limit: int = 100


@dataclass
class ReportingConfig:
    """Configuración de reportes"""
    generate_html: bool = True
    generate_json: bool = True
    report_directory: str = "reports"
    include_timestamps: bool = True
    include_vulnerabilities: bool = True


@dataclass
class SecurityConfig:
    """Configuración de seguridad"""
    max_hosts_per_scan: int = 1000
    require_authorization: bool = True
    log_all_activities: bool = True
    ethical_warning: bool = True


@dataclass
class LoggingConfig:
    """Configuración de logging"""
    log_level: str = "INFO"
    log_file: str = "logs/scanner.log"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_log_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


class ConfigManager:
    """
    Gestor de configuración de la aplicación
    
    Maneja la carga, guardado y validación de configuraciones
    siguiendo patrones de diseño de la industria.
    """
    
    def __init__(self, config_file: str = "config/scanner.conf"):
        self.config_file = Path(config_file)
        self.scanner_config = ScannerConfig()
        self.reporting_config = ReportingConfig()
        self.security_config = SecurityConfig()
        self.logging_config = LoggingConfig()
        
        # Cargar configuración al inicializar
        self.load_config()
    
    def load_config(self) -> bool:
        """
        Carga la configuración desde archivo
        
        Returns:
            True si se cargó correctamente, False en caso contrario
        """
        try:
            if not self.config_file.exists():
                logger.info("Configuration file not found, creating default configuration")
                self.save_config()
                return True
            
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Cargar configuraciones específicas
            if 'scanner' in config_data:
                self._load_scanner_config(config_data['scanner'])
            
            if 'reporting' in config_data:
                self._load_reporting_config(config_data['reporting'])
            
            if 'security' in config_data:
                self._load_security_config(config_data['security'])
            
            if 'logging' in config_data:
                self._load_logging_config(config_data['logging'])
            
            logger.info("Configuration loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def save_config(self) -> bool:
        """
        Guarda la configuración actual en archivo
        
        Returns:
            True si se guardó correctamente, False en caso contrario
        """
        try:
            # Crear directorio si no existe
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                'scanner': asdict(self.scanner_config),
                'reporting': asdict(self.reporting_config),
                'security': asdict(self.security_config),
                'logging': asdict(self.logging_config)
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            logger.info("Configuration saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get_scanner_config(self) -> ScannerConfig:
        """Obtiene la configuración del escáner"""
        return self.scanner_config
    
    def get_reporting_config(self) -> ReportingConfig:
        """Obtiene la configuración de reportes"""
        return self.reporting_config
    
    def get_security_config(self) -> SecurityConfig:
        """Obtiene la configuración de seguridad"""
        return self.security_config
    
    def get_logging_config(self) -> LoggingConfig:
        """Obtiene la configuración de logging"""
        return self.logging_config
    
    def update_scanner_config(self, **kwargs) -> bool:
        """
        Actualiza la configuración del escáner
        
        Args:
            **kwargs: Parámetros a actualizar
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            for key, value in kwargs.items():
                if hasattr(self.scanner_config, key):
                    setattr(self.scanner_config, key, value)
            
            return self.save_config()
            
        except Exception as e:
            logger.error(f"Error updating scanner config: {e}")
            return False
    
    def update_reporting_config(self, **kwargs) -> bool:
        """
        Actualiza la configuración de reportes
        
        Args:
            **kwargs: Parámetros a actualizar
            
        Returns:
            True si se actualizó correctamente
        """
        try:
            for key, value in kwargs.items():
                if hasattr(self.reporting_config, key):
                    setattr(self.reporting_config, key, value)
            
            return self.save_config()
            
        except Exception as e:
            logger.error(f"Error updating reporting config: {e}")
            return False
    
    def validate_config(self) -> bool:
        """
        Valida la configuración actual
        
        Returns:
            True si la configuración es válida
        """
        try:
            # Validar configuración del escáner
            if self.scanner_config.connection_timeout <= 0:
                logger.error("Connection timeout must be positive")
                return False
            
            if self.scanner_config.max_threads <= 0:
                logger.error("Max threads must be positive")
                return False
            
            if self.scanner_config.max_threads > 1000:
                logger.warning("Max threads is very high, consider reducing")
            
            # Validar configuración de reportes
            if not self.reporting_config.report_directory:
                logger.error("Report directory cannot be empty")
                return False
            
            # Validar configuración de seguridad
            if self.security_config.max_hosts_per_scan <= 0:
                logger.error("Max hosts per scan must be positive")
                return False
            
            if self.security_config.max_hosts_per_scan > 10000:
                logger.warning("Max hosts per scan is very high, consider reducing")
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """
        Resetea la configuración a valores por defecto
        
        Returns:
            True si se reseteó correctamente
        """
        try:
            self.scanner_config = ScannerConfig()
            self.reporting_config = ReportingConfig()
            self.security_config = SecurityConfig()
            self.logging_config = LoggingConfig()
            
            return self.save_config()
            
        except Exception as e:
            logger.error(f"Error resetting configuration: {e}")
            return False
    
    def _load_scanner_config(self, config_data: Dict[str, Any]):
        """Carga configuración del escáner"""
        for key, value in config_data.items():
            if hasattr(self.scanner_config, key):
                setattr(self.scanner_config, key, value)
    
    def _load_reporting_config(self, config_data: Dict[str, Any]):
        """Carga configuración de reportes"""
        for key, value in config_data.items():
            if hasattr(self.reporting_config, key):
                setattr(self.reporting_config, key, value)
    
    def _load_security_config(self, config_data: Dict[str, Any]):
        """Carga configuración de seguridad"""
        for key, value in config_data.items():
            if hasattr(self.security_config, key):
                setattr(self.security_config, key, value)
    
    def _load_logging_config(self, config_data: Dict[str, Any]):
        """Carga configuración de logging"""
        for key, value in config_data.items():
            if hasattr(self.logging_config, key):
                setattr(self.logging_config, key, value)
