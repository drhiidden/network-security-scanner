# 🔍 Network Security Scanner - Educational Tool

## 🎓 Proyecto Académico de Ingeniería Informática

**Herramienta educativa para el aprendizaje de técnicas de seguridad de red y red team, desarrollada siguiendo estándares de la industria y mejores prácticas de ingeniería.**

### 📋 Información del Proyecto

- **Autor:** [Tu Nombre]
- **Universidad:** [Nombre de tu Universidad]
- **Curso:** Seguridad Informática / Red Team
- **Fecha:** 2025
- **Licencia:** MIT

## ⚠️ ADVERTENCIA ÉTICA

**Esta herramienta es únicamente para propósitos educativos y de prueba en redes propias o autorizadas. El uso de esta herramienta en redes sin autorización es ilegal y puede resultar en consecuencias legales.**


### 🎯 Características Principales

#### **1. Escaneo de Red Profesional**
- **Descubrimiento de Hosts**: ARP, ICMP, técnicas avanzadas
- **Escaneo de Puertos**: TCP/UDP, múltiples técnicas
- **Enumeración de Servicios**: Identificación automática
- **Escaneo Paralelo**: Optimizado con ThreadPoolExecutor

#### **2. Análisis de Vulnerabilidades**
- **Verificación SSL/TLS**: Versiones, cifrados, certificados
- **Headers de Seguridad HTTP**: CSP, HSTS, X-Frame-Options
- **Análisis de Servicios**: FTP, SSH, SMB, Telnet
- **Detección de Configuraciones Inseguras**

#### **3. Arquitectura de Software**
- **Patrones de Diseño**: Strategy, Template Method, Factory
- **Principios SOLID**: Separación de responsabilidades
- **Gestión de Configuración**: JSON, validación automática
- **Logging Profesional**: Rotación, niveles configurables

#### **4. Generación de Reportes**
- **Reportes HTML**: Profesionales y detallados
- **Reportes JSON**: Para integración con otras herramientas
- **Documentación Automática**: Incluye evidencias y recomendaciones

## 🚀 Instalación y Configuración

### **Requisitos Previos**
- Python 3.7+
- Nmap (para funcionalidades avanzadas)
- Permisos de administrador (para algunas funcionalidades)

## 📖 Uso de la Herramienta

### **Comandos Básicos**

#### **1. Descubrimiento de Hosts**
```bash
# Descubrir hosts en la red local
python main.py --target 192.168.1.0/24 --discovery

# Descubrimiento con configuración personalizada
python main.py --target 192.168.1.0/24 --discovery --threads 200 --timeout 5
```

#### **2. Escaneo de Puertos**
```bash
# Escaneo rápido de puertos comunes
python main.py --target 192.168.1.1 --quick

# Escaneo de puertos específicos
python main.py --target 192.168.1.1 --ports 80,443,22,21,3306

# Escaneo completo de red
python main.py --target 192.168.1.0/24 --comprehensive
```

#### **3. Análisis de Vulnerabilidades**
```bash
# Análisis completo con vulnerabilidades
python main.py --target 192.168.1.1 --comprehensive --report

# Análisis específico de servicios
python main.py --target 192.168.1.1 --ports 443,80 --comprehensive
```

### **Opciones Avanzadas**

```bash
# Escaneo con configuración personalizada
python main.py \
  --target 192.168.1.0/24 \
  --ports 21,22,23,25,53,80,110,143,443,993,995 \
  --threads 150 \
  --timeout 5 \
  --verbose \
  --report \
  --report-type html

# Modo de descubrimiento solo
python main.py --target 192.168.1.0/24 --discovery --verbose
```

## 🛠️ Desarrollo y Extensión

### **Estructura de Clases**

```python
# Ejemplo de uso programático
from src.core.network_scanner import NetworkScanner, ScanConfiguration
from src.core.vulnerability_analyzer import VulnerabilityAnalyzer

# Configurar escaneo
config = ScanConfiguration(
    target="192.168.1.0/24",
    ports=[80, 443, 22, 21],
    timeout=3,
    max_threads=100
)

# Ejecutar escaneo
scanner = NetworkScanner(config)
results = scanner.run_scan()

# Análisis de vulnerabilidades
analyzer = VulnerabilityAnalyzer()
vuln_results = analyzer.analyze_host("192.168.1.1", [80, 443])
```

### **Extensión de Funcionalidades**

```python
# Crear nuevo verificador de seguridad
from src.core.vulnerability_analyzer import BaseSecurityChecker, SecurityCheckResult

class CustomSecurityChecker(BaseSecurityChecker):
    def check(self, target: str, **kwargs) -> SecurityCheckResult:
        # Implementar verificación personalizada
        result = SecurityCheckResult(
            check_name="Custom Check",
            passed=True
        )
        return result
```

## 📊 Generación de Reportes

### **Tipos de Reporte**

1. **HTML**: Reportes visuales y profesionales
2. **JSON**: Para integración con otras herramientas
3. **PDF**: (Próximamente)

### **Ejemplo de Reporte**

```bash
# Generar reporte HTML
python main.py --target 192.168.1.1 --comprehensive --report --report-type html

# El reporte incluye:
# - Resumen ejecutivo
# - Hosts descubiertos
# - Puertos abiertos
# - Vulnerabilidades encontradas
# - Recomendaciones de seguridad
# - Evidencias técnicas
```

## 🔧 Configuración

### **Archivo de Configuración**

```json
{
  "scanner": {
    "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443],
    "connection_timeout": 3,
    "scan_timeout": 30,
    "max_threads": 100,
    "rate_limit": 100
  },
  "reporting": {
    "generate_html": true,
    "generate_json": true,
    "report_directory": "reports",
    "include_timestamps": true,
    "include_vulnerabilities": true
  },
  "security": {
    "max_hosts_per_scan": 1000,
    "require_authorization": true,
    "log_all_activities": true,
    "ethical_warning": true
  }
}
```

## 📚 Aprendizaje y Educación

### **Conceptos de Red Team Cubiertos**

1. **Reconocimiento de Red**
   - Descubrimiento de hosts
   - Enumeración de servicios
   - Mapeo de red

2. **Análisis de Vulnerabilidades**
   - Configuraciones inseguras
   - Servicios vulnerables
   - Headers de seguridad

3. **Documentación Profesional**
   - Generación de reportes
   - Evidencias técnicas
   - Recomendaciones de mitigación

### **Estándares de la Industria**

- **OWASP**: Mejores prácticas de seguridad web
- **NIST**: Framework de ciberseguridad
- **ISO 27001**: Gestión de seguridad de la información
- **MITRE ATT&CK**: Técnicas de ataque y defensa

## 🤝 Contribuciones

### **Cómo Contribuir**

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### **Estándares de Código**

- **PEP 8**: Estilo de código Python
- **Type Hints**: Tipado estático
- **Docstrings**: Documentación de funciones
- **Logging**: Registro de actividades
- **Testing**: Pruebas unitarias (próximamente)

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## ⚖️ Responsabilidad Legal

- Solo usa esta herramienta en redes que poseas o tengas autorización explícita
- No uses para actividades maliciosas o no autorizadas
- Respeta las políticas de seguridad de las organizaciones
- El desarrollador no se hace responsable del uso indebido

## 📞 Contacto

- **Autor:** [Tu Nombre]
- **Email:** [tu.email@universidad.edu]
- **Universidad:** [Nombre de tu Universidad]
- **Curso:** Seguridad Informática

---

**🔒 Recuerda: La seguridad informática es una responsabilidad ética. Usa estas herramientas para aprender y proteger, no para dañar.**
