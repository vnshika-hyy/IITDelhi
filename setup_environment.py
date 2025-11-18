# #!/usr/bin/env python3
# """
# Environment Setup and Verification Script
# for Phishing URL Detection System
# """

# import sys
# import subprocess
# import pkg_resources
# import platform
# import os
# from pathlib import Path

# # Required Python packages
# REQUIRED_PACKAGES = [
#     'pandas>=1.5.0',
#     'numpy>=1.21.0',
#     'scikit-learn>=1.0.0',
#     'scipy>=1.7.0',
#     'xgboost>=1.6.0',
#     'lightgbm>=3.3.0',
#     'joblib>=1.2.0',
#     'imbalanced-learn>=0.10.0',
#     'matplotlib>=3.5.0',
#     'seaborn>=0.11.0',
#     'tldextract>=3.4.0',
#     'python-whois>=0.8.0',
#     'urllib3>=1.26.0',
#     'requests>=2.28.0',
#     'beautifulsoup4>=4.11.0',
#     'lxml>=4.9.0',
#     'Pillow>=9.0.0',
#     'selenium>=4.8.0',
#     'webdriver-manager>=3.8.0',
#     'pdfkit>=1.0.0',
#     'dnspython>=2.2.0',
#     'pyOpenSSL>=22.0.0',
#     'cryptography>=37.0.0',
#     'openpyxl>=3.0.0',
#     'xlrd>=2.0.0',
#     'tqdm>=4.64.0',
#     'python-dateutil>=2.8.0'
# ]

# # System dependencies
# SYSTEM_DEPENDENCIES = {
#     'chrome': {
#         'windows': 'google-chrome',
#         'linux': 'google-chrome-stable',
#         'macos': 'google-chrome'
#     }
# }

# class EnvironmentVerifier:
#     """Verify and setup the environment for phishing detection system"""
    
#     def __init__(self):
#         self.os_type = self.detect_os()
#         self.issues = []
#         self.warnings = []
        
#     def detect_os(self):
#         """Detect the operating system"""
#         system = platform.system().lower()
#         if system == 'windows':
#             return 'windows'
#         elif system == 'darwin':
#             return 'macos'
#         else:
#             return 'linux'
    
#     def print_header(self, text):
#         """Print formatted header"""
#         print(f"\n{'='*60}")
#         print(f"🔧 {text}")
#         print(f"{'='*60}")
    
#     def print_success(self, text):
#         """Print success message"""
#         print(f"✅ {text}")
    
#     def print_warning(self, text):
#         """Print warning message"""
#         print(f"⚠️  {text}")
#         self.warnings.append(text)
    
#     def print_error(self, text):
#         """Print error message"""
#         print(f"❌ {text}")
#         self.issues.append(text)
    
#     def check_python_version(self):
#         """Check Python version compatibility"""
#         self.print_header("Checking Python Version")
        
#         python_version = sys.version_info
#         version_str = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
        
#         if python_version >= (3, 8):
#             self.print_success(f"Python {version_str} (Compatible)")
#             return True
#         else:
#             self.print_error(f"Python {version_str} - Python 3.8+ required")
#             return False
    
#     def check_python_packages(self):
#         """Check required Python packages"""
#         self.print_header("Checking Python Packages")
        
#         missing_packages = []
#         version_issues = []
        
#         for package_spec in REQUIRED_PACKAGES:
#             try:
#                 # Extract package name from spec
#                 package_name = package_spec.split('>=')[0].split('<')[0].split('==')[0].strip()
#                 pkg_resources.require(package_spec)
#                 version = pkg_resources.get_distribution(package_name).version
#                 self.print_success(f"{package_name:20} v{version}")
#             except pkg_resources.DistributionNotFound:
#                 missing_packages.append(package_name)
#                 self.print_error(f"{package_name:20} - Not installed")
#             except pkg_resources.VersionConflict as e:
#                 version_issues.append(package_name)
#                 self.print_warning(f"{package_name:20} - Version conflict: {e}")
        
#         if missing_packages or version_issues:
#             self.print_warning(f"Missing: {len(missing_packages)}, Version issues: {len(version_issues)}")
#             return False
#         else:
#             self.print_success("All Python packages are installed correctly!")
#             return True
    
#     def check_system_dependency(self, dependency_name):
#         """Check if a system dependency is installed"""
#         command = None
        
#         if dependency_name == 'chrome':
#             if self.os_type == 'windows':
#                 command = ['reg', 'query', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\BLBeacon']
#             else:
#                 command = ['google-chrome', '--version']
        
#         if not command:
#             return False
        
#         try:
#             result = subprocess.run(command, capture_output=True, text=True, timeout=10)
#             if result.returncode == 0:
#                 return True
#         except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
#             pass
        
#         return False
    
#     def check_system_dependencies(self):
#         """Check all system dependencies"""
#         self.print_header("Checking System Dependencies")
        
#         all_available = True
        
#         for dep_name, dep_commands in SYSTEM_DEPENDENCIES.items():
#             if self.check_system_dependency(dep_name):
#                 self.print_success(f"{dep_name:15} - Installed")
#             else:
#                 self.print_warning(f"{dep_name:15} - Not found (optional for Selenium)")
#                 self.print_installation_help(dep_name)
        
#         return all_available
    
#     def print_installation_help(self, dependency):
#         """Print installation help for missing dependencies"""
#         print(f"   💡 Installation help for {dependency}:")
        
#         if self.os_type == 'windows':
#             if dependency == 'chrome':
#                 print("   Download from: https://www.google.com/chrome/")
#             print("   Or use: choco install", SYSTEM_DEPENDENCIES[dependency]['windows'])
                
#         elif self.os_type == 'linux':
#             print("   sudo apt update && sudo apt install", SYSTEM_DEPENDENCIES[dependency]['linux'])
            
#         elif self.os_type == 'macos':
#             print("   brew install", SYSTEM_DEPENDENCIES[dependency]['macos'])
    
#     def check_folder_structure(self):
#         """Check and create required folder structure"""
#         self.print_header("Checking Folder Structure")
        
#         required_folders = [
#             'Dataset',
#             'models',
#             'submissions',
#             'logs',
#             'src'
#         ]
        
#         all_created = True
        
#         for folder in required_folders:
#             folder_path = Path(folder)
#             if folder_path.exists():
#                 self.print_success(f"{folder:15} - Exists")
#             else:
#                 try:
#                     folder_path.mkdir(parents=True, exist_ok=True)
#                     self.print_success(f"{folder:15} - Created")
#                 except Exception as e:
#                     self.print_error(f"{folder:15} - Failed to create: {str(e)}")
#                     all_created = False
        
#         return all_created
    
#     def check_sample_files(self):
#         """Check for required sample files"""
#         self.print_header("Checking Required Files")
        
#         required_files = {
#             'Dataset/phishing_site_urls.csv': 'Original dataset file',
#             'requirements.txt': 'Python dependencies list'
#         }
        
#         all_exist = True
        
#         for file_path, description in required_files.items():
#             if Path(file_path).exists():
#                 self.print_success(f"{file_path:30} - Found")
#             else:
#                 self.print_warning(f"{file_path:30} - Missing: {description}")
#                 all_exist = False
        
#         return all_exist
    
#     def install_missing_packages(self):
#         """Install missing Python packages"""
#         self.print_header("Installing Missing Packages")
        
#         missing_packages = []
        
#         # First, identify missing packages
#         for package_spec in REQUIRED_PACKAGES:
#             package_name = package_spec.split('>=')[0].split('<')[0].split('==')[0].strip()
#             try:
#                 pkg_resources.require(package_spec)
#             except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
#                 missing_packages.append(package_name)
        
#         if not missing_packages:
#             self.print_success("No missing packages to install!")
#             return True
        
#         print(f"📦 Installing {len(missing_packages)} missing packages...")
        
#         success_count = 0
#         for package in missing_packages:
#             try:
#                 print(f"Installing {package}...", end=" ")
#                 subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
#                 print("✅")
#                 success_count += 1
#             except subprocess.CalledProcessError:
#                 print("❌")
#                 self.print_error(f"Failed to install {package}")
        
#         if success_count == len(missing_packages):
#             self.print_success("All packages installed successfully!")
#             return True
#         else:
#             self.print_error(f"Failed to install {len(missing_packages) - success_count} packages")
#             return False
    
#     def run_comprehensive_check(self, auto_install=False):
#         """Run comprehensive environment check"""
#         print("🚀 Phishing Detection System - Environment Verification")
#         print("=" * 60)
        
#         checks = []
        
#         # Run all checks
#         checks.append(self.check_python_version())
#         checks.append(self.check_python_packages())
#         checks.append(self.check_system_dependencies())
#         checks.append(self.check_folder_structure())
#         checks.append(self.check_sample_files())
        
#         # Install missing packages if requested
#         if auto_install and not all(checks[1:2]):  # If package check failed
#             if self.install_missing_packages():
#                 # Re-check packages after installation
#                 checks[1] = self.check_python_packages()
        
#         # Summary
#         self.print_header("VERIFICATION SUMMARY")
        
#         total_checks = len(checks)
#         passed_checks = sum(checks)
        
#         if passed_checks == total_checks:
#             print("🎉 ALL CHECKS PASSED! Environment is ready.")
#             print("\nYou can now run the phishing detection system:")
#             print("  python src/feature_extractor.py    # Extract features")
#             print("  python src/model_trainer.py        # Train models")
#             print("  python predictor.py --url <URL>    # Predict single URL")
#         else:
#             print(f"⚠️  {passed_checks}/{total_checks} checks passed")
            
#             if self.issues:
#                 print("\n❌ Critical issues that need fixing:")
#                 for issue in self.issues:
#                     print(f"  - {issue}")
            
#             if self.warnings:
#                 print("\n⚠️  Warnings (may not prevent operation):")
#                 for warning in self.warnings:
#                     print(f"  - {warning}")
        
#         return all(checks)


# def main():
#     """Main function"""
#     import argparse
    
#     parser = argparse.ArgumentParser(description='Environment Setup Verification')
#     parser.add_argument('--auto-install', '-a', action='store_true',
#                        help='Automatically install missing Python packages')
#     parser.add_argument('--skip-system', '-s', action='store_true',
#                        help='Skip system dependency checks')
    
#     args = parser.parse_args()
    
#     verifier = EnvironmentVerifier()
    
#     if args.skip_system:
#         # Modify to skip system checks
#         original_system_check = verifier.check_system_dependencies
#         verifier.check_system_dependencies = lambda: True
    
#     success = verifier.run_comprehensive_check(auto_install=args.auto_install)
    
#     # Exit with appropriate code
#     sys.exit(0 if success else 1)


# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
Environment Setup and Verification Script
for Phishing URL Detection System
"""

import sys
import subprocess
import pkg_resources
import platform
import os
from pathlib import Path

# Required Python packages - Updated to match requirements.txt
REQUIRED_PACKAGES = [
    'pandas>=1.5.0',
    'numpy>=1.21.0',
    'scikit-learn>=1.0.0',
    'scipy>=1.7.0',
    'xgboost>=1.6.0',
    'lightgbm>=3.3.0',
    'joblib>=1.2.0',
    'imbalanced-learn>=0.10.0',
    'matplotlib>=3.5.0',
    'seaborn>=0.11.0',
    'tldextract>=3.4.0',
    'python-whois>=0.8.0',
    'urllib3>=1.26.0',
    'requests>=2.28.0',
    'beautifulsoup4>=4.11.0',
    'lxml>=4.9.0',
    'dnspython>=2.2.0',
    'Pillow>=9.0.0',
    'selenium>=4.8.0',
    'webdriver-manager>=3.8.0',
    'pdfkit>=1.0.0',
    'pyOpenSSL>=22.0.0',
    'cryptography>=37.0.0',
    'openpyxl>=3.0.0',
    'xlrd>=2.0.0',
    'tqdm>=4.64.0',
    'python-dateutil>=2.8.0'
]

# Optional packages (for enhanced functionality)
OPTIONAL_PACKAGES = [
    'plotly>=5.10.0',
    'opencv-python>=4.6.0',
    'pytesseract>=0.3.0',
    'scikit-image>=0.19.0',
    'Jinja2>=3.0.0',
    'reportlab>=3.6.0',
    'numba>=0.56.0'
]

# System dependencies
SYSTEM_DEPENDENCIES = {
    'chrome': {
        'windows': 'google-chrome',
        'linux': 'google-chrome-stable',
        'macos': 'google-chrome'
    },
    'wkhtmltopdf': {
        'windows': 'wkhtmltopdf',
        'linux': 'wkhtmltopdf',
        'macos': 'wkhtmltopdf'
    }
}

class EnvironmentVerifier:
    """Verify and setup the environment for phishing detection system"""
    
    def __init__(self):
        self.os_type = self.detect_os()
        self.issues = []
        self.warnings = []
        self.optional_missing = []
        
    def detect_os(self):
        """Detect the operating system"""
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'darwin':
            return 'macos'
        else:
            return 'linux'
    
    def print_header(self, text):
        """Print formatted header"""
        print(f"\n{'='*60}")
        print(f"🔧 {text}")
        print(f"{'='*60}")
    
    def print_success(self, text):
        """Print success message"""
        print(f"✅ {text}")
    
    def print_warning(self, text):
        """Print warning message"""
        print(f"⚠️  {text}")
        self.warnings.append(text)
    
    def print_error(self, text):
        """Print error message"""
        print(f"❌ {text}")
        self.issues.append(text)
    
    def print_info(self, text):
        """Print info message"""
        print(f"ℹ️  {text}")
    
    def check_python_version(self):
        """Check Python version compatibility"""
        self.print_header("Checking Python Version")
        
        python_version = sys.version_info
        version_str = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
        
        if python_version >= (3, 8):
            self.print_success(f"Python {version_str} (Compatible)")
            return True
        else:
            self.print_error(f"Python {version_str} - Python 3.8+ required")
            return False
    
    def check_python_packages(self):
        """Check required Python packages"""
        self.print_header("Checking Required Python Packages")
        
        missing_packages = []
        version_issues = []
        
        for package_spec in REQUIRED_PACKAGES:
            try:
                # Extract package name from spec
                package_name = package_spec.split('>=')[0].split('<')[0].split('==')[0].strip()
                pkg_resources.require(package_spec)
                version = pkg_resources.get_distribution(package_name).version
                self.print_success(f"{package_name:25} v{version}")
            except pkg_resources.DistributionNotFound:
                missing_packages.append(package_name)
                self.print_error(f"{package_name:25} - Not installed")
            except pkg_resources.VersionConflict as e:
                version_issues.append(package_name)
                self.print_warning(f"{package_name:25} - Version conflict: {e}")
        
        # Check optional packages
        self.print_header("Checking Optional Packages")
        for package_spec in OPTIONAL_PACKAGES:
            try:
                package_name = package_spec.split('>=')[0].split('<')[0].split('==')[0].strip()
                pkg_resources.require(package_spec)
                version = pkg_resources.get_distribution(package_name).version
                self.print_success(f"{package_name:25} v{version}")
            except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                self.optional_missing.append(package_name)
                self.print_info(f"{package_name:25} - Not installed (optional)")
        
        if missing_packages or version_issues:
            self.print_warning(f"Missing: {len(missing_packages)}, Version issues: {len(version_issues)}")
            return False
        else:
            self.print_success("All required Python packages are installed correctly!")
            return True
    
    def check_system_dependency(self, dependency_name):
        """Check if a system dependency is installed"""
        command = None
        
        if dependency_name == 'chrome':
            if self.os_type == 'windows':
                # Try multiple ways to detect Chrome on Windows
                commands = [
                    ['reg', 'query', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\BLBeacon'],
                    ['powershell', '-command', 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"'],
                    ['where', 'chrome.exe']
                ]
            else:
                commands = [['google-chrome', '--version']]
        
        elif dependency_name == 'wkhtmltopdf':
            if self.os_type == 'windows':
                commands = [['where', 'wkhtmltopdf.exe'], ['wkhtmltopdf', '--version']]
            else:
                commands = [['which', 'wkhtmltopdf'], ['wkhtmltopdf', '--version']]
        
        if not command:
            # Try all commands for the dependency
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                    continue
        
        return False
    
    def check_system_dependencies(self):
        """Check all system dependencies"""
        self.print_header("Checking System Dependencies")
        
        all_available = True
        
        for dep_name, dep_commands in SYSTEM_DEPENDENCIES.items():
            if self.check_system_dependency(dep_name):
                self.print_success(f"{dep_name:20} - Installed")
            else:
                if dep_name == 'chrome':
                    self.print_warning(f"{dep_name:20} - Not found (required for Selenium screenshots)")
                else:
                    self.print_info(f"{dep_name:20} - Not found (optional for PDF generation)")
                self.print_installation_help(dep_name)
                if dep_name == 'chrome':
                    all_available = False
        
        return all_available
    
    def print_installation_help(self, dependency):
        """Print installation help for missing dependencies"""
        print(f"   💡 Installation help for {dependency}:")
        
        if dependency == 'chrome':
            if self.os_type == 'windows':
                print("   Download from: https://www.google.com/chrome/")
                print("   Or use: choco install google-chrome")
            elif self.os_type == 'linux':
                print("   sudo apt update && sudo apt install google-chrome-stable")
                print("   Or: wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && sudo dpkg -i google-chrome-stable_current_amd64.deb")
            elif self.os_type == 'macos':
                print("   brew install --cask google-chrome")
                print("   Or download from: https://www.google.com/chrome/")
        
        elif dependency == 'wkhtmltopdf':
            if self.os_type == 'windows':
                print("   Download from: https://wkhtmltopdf.org/downloads.html")
                print("   Or use: choco install wkhtmltopdf")
            elif self.os_type == 'linux':
                print("   sudo apt install wkhtmltopdf")
            elif self.os_type == 'macos':
                print("   brew install wkhtmltopdf")
    
    def check_folder_structure(self):
        """Check and create required folder structure"""
        self.print_header("Checking Folder Structure")
        
        required_folders = [
            'Dataset',
            'models',
            'submissions',
            'logs',
            'src',
            'reports',
            'screenshots',
            'temp'
        ]
        
        all_created = True
        
        for folder in required_folders:
            folder_path = Path(folder)
            if folder_path.exists():
                self.print_success(f"{folder:15} - Exists")
            else:
                try:
                    folder_path.mkdir(parents=True, exist_ok=True)
                    self.print_success(f"{folder:15} - Created")
                except Exception as e:
                    self.print_error(f"{folder:15} - Failed to create: {str(e)}")
                    all_created = False
        
        return all_created
    
    def check_sample_files(self):
        """Check for required sample files"""
        self.print_header("Checking Required Files")
        
        required_files = {
            'Dataset/phishing_site_urls.csv': 'Original dataset file',
            'requirements.txt': 'Python dependencies list',
            'src/feature_extractor.py': 'Feature extraction module',
            'src/model_trainer.py': 'Model training module'
        }
        
        all_exist = True
        
        for file_path, description in required_files.items():
            if Path(file_path).exists():
                self.print_success(f"{file_path:35} - Found")
            else:
                self.print_warning(f"{file_path:35} - Missing: {description}")
                all_exist = False
        
        return all_exist
    
    def install_missing_packages(self):
        """Install missing Python packages"""
        self.print_header("Installing Missing Packages")
        
        missing_packages = []
        
        # First, identify missing packages
        for package_spec in REQUIRED_PACKAGES:
            package_name = package_spec.split('>=')[0].split('<')[0].split('==')[0].strip()
            try:
                pkg_resources.require(package_spec)
            except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                missing_packages.append(package_spec)  # Use full spec for installation
        
        if not missing_packages:
            self.print_success("No missing packages to install!")
            return True
        
        print(f"📦 Installing {len(missing_packages)} missing packages...")
        
        success_count = 0
        for package in missing_packages:
            try:
                print(f"Installing {package}...", end=" ")
                # Use the full package spec for installation
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package, '--quiet'])
                print("✅")
                success_count += 1
            except subprocess.CalledProcessError as e:
                print("❌")
                self.print_error(f"Failed to install {package}: {e}")
        
        if success_count == len(missing_packages):
            self.print_success("All packages installed successfully!")
            return True
        else:
            self.print_warning(f"Installed {success_count}/{len(missing_packages)} packages")
            return False
    
    def check_disk_space(self):
        """Check available disk space"""
        self.print_header("Checking Disk Space")
        
        try:
            if self.os_type == 'windows':
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(os.getcwd()), None, None, ctypes.pointer(free_bytes))
                free_gb = free_bytes.value / (1024**3)
            else:
                stat = os.statvfs('.')
                free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            
            if free_gb > 5:  # 5GB threshold
                self.print_success(f"Disk space: {free_gb:.1f} GB available")
                return True
            else:
                self.print_warning(f"Low disk space: {free_gb:.1f} GB available (recommended: 5+ GB)")
                return True  # Not critical, just a warning
                
        except Exception as e:
            self.print_warning(f"Could not check disk space: {e}")
            return True
    
    def check_memory(self):
        """Check system memory"""
        self.print_header("Checking System Memory")
        
        try:
            if self.os_type == 'windows':
                import psutil
                memory = psutil.virtual_memory()
                total_gb = memory.total / (1024**3)
                if total_gb >= 8:
                    self.print_success(f"System RAM: {total_gb:.1f} GB")
                else:
                    self.print_warning(f"Low system RAM: {total_gb:.1f} GB (recommended: 8+ GB)")
            else:
                # For Linux/Mac, use psutil if available
                try:
                    import psutil
                    memory = psutil.virtual_memory()
                    total_gb = memory.total / (1024**3)
                    if total_gb >= 8:
                        self.print_success(f"System RAM: {total_gb:.1f} GB")
                    else:
                        self.print_warning(f"Low system RAM: {total_gb:.1f} GB (recommended: 8+ GB)")
                except ImportError:
                    self.print_info("Install 'psutil' for detailed memory information")
            
            return True
        except Exception as e:
            self.print_warning(f"Could not check memory: {e}")
            return True
    
    def run_comprehensive_check(self, auto_install=False):
        """Run comprehensive environment check"""
        print("🚀 Phishing Detection System - Environment Verification")
        print("=" * 60)
        
        checks = []
        
        # Run all checks
        checks.append(self.check_python_version())
        checks.append(self.check_python_packages())
        checks.append(self.check_system_dependencies())
        checks.append(self.check_folder_structure())
        checks.append(self.check_sample_files())
        checks.append(self.check_disk_space())
        checks.append(self.check_memory())
        
        # Install missing packages if requested
        if auto_install and not all(checks[1:2]):  # If package check failed
            if self.install_missing_packages():
                # Re-check packages after installation
                checks[1] = self.check_python_packages()
        
        # Summary
        self.print_header("VERIFICATION SUMMARY")
        
        total_checks = len(checks)
        passed_checks = sum(checks)
        
        if passed_checks == total_checks:
            print("🎉 ALL CHECKS PASSED! Environment is ready.")
            print("\nYou can now run the phishing detection system:")
            print("  python src/feature_extractor.py    # Extract features")
            print("  python src/model_trainer.py        # Train models")
            print("  python predictor.py --url <URL>    # Predict single URL")
        else:
            print(f"⚠️  {passed_checks}/{total_checks} checks passed")
            
            if self.issues:
                print("\n❌ Critical issues that need fixing:")
                for issue in self.issues:
                    print(f"  - {issue}")
            
            if self.warnings:
                print("\n⚠️  Warnings (may not prevent operation):")
                for warning in self.warnings:
                    print(f"  - {warning}")
            
            if self.optional_missing:
                print("\n💡 Optional packages not installed:")
                for package in self.optional_missing:
                    print(f"  - {package}")
                print("\n  To install optional packages: pip install " + " ".join(self.optional_missing))
        
        return all(checks)


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Environment Setup Verification')
    parser.add_argument('--auto-install', '-a', action='store_true',
                       help='Automatically install missing Python packages')
    parser.add_argument('--skip-system', '-s', action='store_true',
                       help='Skip system dependency checks')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    verifier = EnvironmentVerifier()
    
    if args.skip_system:
        # Modify to skip system checks
        original_system_check = verifier.check_system_dependencies
        verifier.check_system_dependencies = lambda: True
    
    success = verifier.run_comprehensive_check(auto_install=args.auto_install)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()