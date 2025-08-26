"""
🔍 Network Security Scanner - Educational Tool
Herramienta Educativa para Ingeniería Informática

Este paquete proporciona herramientas completas para el aprendizaje de
técnicas de seguridad de red y red team, siguiendo estándares de la industria.

Autor: [Tu Nombre]
Universidad: [Nombre de tu Universidad]
Curso: Seguridad Informática / Red Team
"""

__version__ = "1.0.0"
__author__ = "[Tu Nombre]"
__email__ = "[tu.email@universidad.edu]"
__license__ = "MIT"

# Importaciones principales para facilitar el uso
from .core.network_scanner import NetworkScanner
from .core.vulnerability_analyzer import VulnerabilityAnalyzer
from .core.reconnaissance import ReconnaissanceEngine
from .utils.report_generator import ReportGenerator
from .utils.config_manager import ConfigManager

__all__ = [
    'NetworkScanner',
    'VulnerabilityAnalyzer', 
    'ReconnaissanceEngine',
    'ReportGenerator',
    'ConfigManager'
]
