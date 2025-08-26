#!/usr/bin/env python3
"""
🔧 Script de Configuración para Escáner de Red
Herramienta Educativa de Red Team
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Verifica la versión de Python"""
    if sys.version_info < (3, 7):
        print("❌ Error: Se requiere Python 3.7 o superior")
        print(f"   Versión actual: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} detectado")
    return True

def install_dependencies():
    """Instala las dependencias de Python"""
    print("📦 Instalando dependencias de Python...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencias instaladas correctamente")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error instalando dependencias: {e}")
        return False

def check_nmap():
    """Verifica si Nmap está instalado"""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Nmap detectado")
            return True
    except FileNotFoundError:
        pass
    
    print("⚠️ Nmap no detectado")
    return False

def install_nmap_windows():
    """Instala Nmap en Windows"""
    print("📦 Instalando Nmap...")
    
    try:
        # Intentar con winget
        subprocess.check_call(["winget", "install", "nmap.nmap"])
        print("✅ Nmap instalado con winget")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️ winget no disponible, intentando con chocolatey...")
        
        try:
            subprocess.check_call(["choco", "install", "nmap"])
            print("✅ Nmap instalado con chocolatey")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("❌ No se pudo instalar Nmap automáticamente")
            print("💡 Instala Nmap manualmente desde: https://nmap.org/download.html")
            return False

def create_directories():
    """Crea directorios necesarios"""
    directories = ["reports", "logs", "config"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"📁 Directorio creado: {directory}")

def create_config_file():
    """Crea archivo de configuración por defecto"""
    config_content = """# Configuración del Escáner de Red
# Herramienta Educativa de Red Team

[SCANNER]
# Puertos por defecto para escanear
default_ports = 21,22,23,25,53,80,110,143,443,993,995,8080,8443

# Configuración de timeouts
connection_timeout = 3
scan_timeout = 30

# Configuración de hilos
max_threads = 100

[REPORTING]
# Configuración de reportes
generate_html = true
generate_json = true
report_directory = reports

[SECURITY]
# Configuración de seguridad
max_hosts_per_scan = 1000
rate_limit = 100

[LOGGING]
# Configuración de logging
log_level = INFO
log_file = logs/scanner.log
"""
    
    config_path = Path("config/scanner.conf")
    config_path.parent.mkdir(exist_ok=True)
    
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_content)
        print("📄 Archivo de configuración creado: config/scanner.conf")

def create_example_scripts():
    """Crea scripts de ejemplo"""
    examples = {
        "ejemplo_escaneo_basico.bat": """@echo off
echo Ejecutando escaneo basico de red local...
python network_scanner.py --target 192.168.1.0/24
pause""",
        
        "ejemplo_escaneo_completo.bat": """@echo off
echo Ejecutando escaneo completo con analisis de vulnerabilidades...
python network_scanner.py --target 192.168.1.0/24 --vuln-scan --report
pause""",
        
        "ejemplo_escaneo_puertos.bat": """@echo off
echo Escaneando puertos especificos...
python network_scanner.py --target 192.168.1.1 --ports 80,443,22,21
pause""",
        
        "ejemplo_descubrimiento.bat": """@echo off
echo Descubriendo hosts en la red...
python network_scanner.py --target 192.168.1.0/24 --discovery
pause"""
    }
    
    for filename, content in examples.items():
        with open(filename, 'w') as f:
            f.write(content)
        print(f"📄 Script de ejemplo creado: {filename}")

def main():
    """Función principal de configuración"""
    print("🔧 Configurando Escáner de Red para Red Team")
    print("=" * 50)
    
    # Verificar Python
    if not check_python_version():
        return False
    
    # Instalar dependencias
    if not install_dependencies():
        return False
    
    # Verificar/instalar Nmap
    if not check_nmap():
        if platform.system() == "Windows":
            install_nmap_windows()
        else:
            print("💡 Instala Nmap manualmente desde: https://nmap.org/download.html")
    
    # Crear directorios
    create_directories()
    
    # Crear archivo de configuración
    create_config_file()
    
    # Crear scripts de ejemplo
    create_example_scripts()
    
    print("\n" + "=" * 50)
    print("✅ Configuración completada exitosamente!")
    print("\n📋 Próximos pasos:")
    print("1. Ejecuta uno de los scripts de ejemplo:")
    print("   - ejemplo_escaneo_basico.bat")
    print("   - ejemplo_escaneo_completo.bat")
    print("2. Lee el README.md para más información")
    print("3. Asegúrate de usar solo en redes autorizadas")
    
    return True

if __name__ == "__main__":
    main()
