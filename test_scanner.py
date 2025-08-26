#!/usr/bin/env python3
"""
Test Script for Network Security Scanner
Script de Prueba para el Escáner de Seguridad de Red

Este script verifica que todos los componentes del escáner funcionen correctamente
y proporciona ejemplos de uso para aprendizaje.
"""

import sys
import time
from pathlib import Path

# Agregar el directorio raíz al path para importar módulos
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Prueba que todos los módulos se importen correctamente"""
    print("🔍 Testing module imports...")
    
    try:
        # Probar importaciones principales
        from src.core.network_scanner import NetworkScanner, ScanConfiguration
        print("✅ NetworkScanner imported successfully")
        
        from src.core.vulnerability_analyzer import VulnerabilityAnalyzer
        print("✅ VulnerabilityAnalyzer imported successfully")
        
        from src.utils.config_manager import ConfigManager
        print("✅ ConfigManager imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_configuration():
    """Prueba el gestor de configuración"""
    print("\n🔧 Testing configuration manager...")
    
    try:
        from src.utils.config_manager import ConfigManager
        
        config_manager = ConfigManager()
        
        # Probar configuración del escáner
        scanner_config = config_manager.get_scanner_config()
        print(f"✅ Scanner config loaded: {len(scanner_config.default_ports)} default ports")
        
        # Probar configuración de reportes
        reporting_config = config_manager.get_reporting_config()
        print(f"✅ Reporting config loaded: HTML={reporting_config.generate_html}")
        
        # Probar validación
        is_valid = config_manager.validate_config()
        print(f"✅ Configuration validation: {'PASSED' if is_valid else 'FAILED'}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_network_scanner():
    """Prueba el escáner de red con localhost"""
    print("\n🌐 Testing network scanner with localhost...")
    
    try:
        from src.core.network_scanner import NetworkScanner, ScanConfiguration
        
        # Configurar escaneo de localhost
        config = ScanConfiguration(
            target="127.0.0.1",
            ports=[80, 443, 22, 21],
            timeout=2,
            max_threads=10
        )
        
        scanner = NetworkScanner(config)
        
        # Ejecutar escaneo
        print("🔍 Running scan...")
        results = scanner.run_scan()
        
        print(f"✅ Scan completed: {len(results)} hosts found")
        
        # Mostrar resultados
        for result in results:
            print(f"  📍 {result.host_ip}: {len(result.open_ports)} open ports")
            for port in result.open_ports:
                print(f"    🔓 Port {port['port']} ({port['service']})")
        
        return True
        
    except Exception as e:
        print(f"❌ Network scanner test failed: {e}")
        return False

def test_vulnerability_analyzer():
    """Prueba el analizador de vulnerabilidades"""
    print("\n⚠️ Testing vulnerability analyzer...")
    
    try:
        from src.core.vulnerability_analyzer import VulnerabilityAnalyzer
        
        analyzer = VulnerabilityAnalyzer()
        
        # Probar análisis de localhost
        print("🔍 Analyzing localhost vulnerabilities...")
        results = analyzer.analyze_host("127.0.0.1", [80, 443])
        
        print(f"✅ Vulnerability analysis completed: {len(results)} checks performed")
        
        # Mostrar resultados
        for result in results:
            status = "✅ PASSED" if result.passed else "❌ FAILED"
            print(f"  {status} {result.check_name}")
            
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    print(f"    ⚠️ {vuln.severity.value}: {vuln.description}")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability analyzer test failed: {e}")
        return False

def test_quick_functions():
    """Prueba las funciones de utilidad"""
    print("\n⚡ Testing quick utility functions...")
    
    try:
        from src.core.network_scanner import quick_scan
        from src.core.vulnerability_analyzer import analyze_host_vulnerabilities
        
        # Probar escaneo rápido
        print("🔍 Testing quick scan...")
        results = quick_scan("127.0.0.1", [80, 443])
        print(f"✅ Quick scan completed: {len(results)} results")
        
        # Probar análisis rápido de vulnerabilidades
        print("⚠️ Testing quick vulnerability analysis...")
        vuln_results = analyze_host_vulnerabilities("127.0.0.1", [80, 443])
        print(f"✅ Quick vulnerability analysis completed: {len(vuln_results)} results")
        
        return True
        
    except Exception as e:
        print(f"❌ Quick functions test failed: {e}")
        return False

def run_demo():
    """Ejecuta una demostración completa"""
    print("\n🎯 Running complete demonstration...")
    
    try:
        from src.core.network_scanner import NetworkScanner, ScanConfiguration
        from src.core.vulnerability_analyzer import VulnerabilityAnalyzer
        
        # Paso 1: Descubrimiento
        print("🔍 Step 1: Host Discovery")
        discovery_config = ScanConfiguration(target="127.0.0.1")
        discovery_scanner = NetworkScanner(discovery_config)
        hosts = discovery_scanner.run_scan(discovery_only=True)
        print(f"✅ Found {len(hosts)} hosts")
        
        # Paso 2: Escaneo de puertos
        print("🔍 Step 2: Port Scanning")
        scan_config = ScanConfiguration(
            target="127.0.0.1",
            ports=[80, 443, 22, 21, 3306, 5432],
            timeout=2
        )
        port_scanner = NetworkScanner(scan_config)
        scan_results = port_scanner.run_scan()
        print(f"✅ Port scan completed")
        
        # Paso 3: Análisis de vulnerabilidades
        print("⚠️ Step 3: Vulnerability Analysis")
        analyzer = VulnerabilityAnalyzer()
        
        for result in scan_results:
            if result.open_ports:
                open_ports = [port['port'] for port in result.open_ports]
                vuln_results = analyzer.analyze_host(result.host_ip, open_ports)
                print(f"✅ Analyzed {result.host_ip}: {len(vuln_results)} security checks")
        
        print("🎉 Complete demonstration finished successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return False

def main():
    """Función principal de pruebas"""
    print("🧪 NETWORK SECURITY SCANNER - TEST SUITE")
    print("=" * 50)
    
    # Lista de pruebas
    tests = [
        ("Module Imports", test_imports),
        ("Configuration Manager", test_configuration),
        ("Network Scanner", test_network_scanner),
        ("Vulnerability Analyzer", test_vulnerability_analyzer),
        ("Quick Functions", test_quick_functions),
        ("Complete Demo", run_demo)
    ]
    
    # Ejecutar pruebas
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    # Resumen final
    print("\n" + "=" * 50)
    print(f"📊 TEST RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The scanner is ready to use.")
        print("\n💡 Next steps:")
        print("1. Run: python main.py --help")
        print("2. Try: python main.py --target 127.0.0.1 --discovery")
        print("3. Explore: python main.py --target 127.0.0.1 --quick")
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
        print("\n🔧 Troubleshooting:")
        print("1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check that you're running from the project root directory")
        print("3. Verify Python version (3.7+ required)")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
