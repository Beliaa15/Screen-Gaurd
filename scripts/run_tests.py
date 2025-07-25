"""
Test runner script for the Physical Security System.
Provides comprehensive testing capabilities with coverage reporting.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path


class TestRunner:
    """Comprehensive test runner for the security system."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        self.src_dir = self.project_root / "src"
    
    def run_all_tests(self):
        """Run all tests with coverage."""
        print("🧪 Running all tests with coverage...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "--cov=src",
            "--cov-report=html",
            "--cov-report=term-missing",
            "--cov-report=xml",
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_unit_tests(self):
        """Run only unit tests."""
        print("🔬 Running unit tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", "unit",
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_integration_tests(self):
        """Run only integration tests."""
        print("🔗 Running integration tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", "integration",
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_auth_tests(self):
        """Run authentication-related tests."""
        print("🔐 Running authentication tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "test_auth.py"),
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_detection_tests(self):
        """Run detection-related tests."""
        print("👁️ Running detection tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "test_detection.py"),
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_security_tests(self):
        """Run security monitoring tests."""
        print("🛡️ Running security tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "test_security.py"),
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_ui_tests(self):
        """Run UI-related tests."""
        print("🖥️ Running UI tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "test_ui.py"),
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_utils_tests(self):
        """Run utility tests."""
        print("🔧 Running utility tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "test_utils.py"),
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_fast_tests(self):
        """Run fast tests only (excludes slow tests)."""
        print("⚡ Running fast tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", "not slow",
            "-v"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def run_with_coverage_report(self):
        """Run tests and generate detailed coverage report."""
        print("📊 Running tests with detailed coverage report...")
        
        # Run tests with coverage
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "--cov=src",
            "--cov-report=html:htmlcov",
            "--cov-report=term-missing",
            "--cov-report=xml:coverage.xml",
            "--cov-fail-under=80",
            "-v"
        ]
        
        result = subprocess.run(cmd, cwd=self.project_root)
        
        if result.returncode == 0:
            print("\n✅ Coverage report generated:")
            print(f"   📄 HTML: {self.project_root}/htmlcov/index.html")
            print(f"   📊 XML: {self.project_root}/coverage.xml")
        
        return result
    
    def lint_code(self):
        """Run code linting checks."""
        print("🔍 Running code linting...")
        
        # Check if flake8 is available
        try:
            cmd = [sys.executable, "-m", "flake8", str(self.src_dir)]
            return subprocess.run(cmd, cwd=self.project_root)
        except FileNotFoundError:
            print("⚠️ flake8 not installed. Install with: pip install flake8")
            return subprocess.CompletedProcess([], 1)
    
    def format_code(self):
        """Format code using black."""
        print("🎨 Formatting code...")
        
        try:
            cmd = [sys.executable, "-m", "black", str(self.src_dir), str(self.test_dir)]
            return subprocess.run(cmd, cwd=self.project_root)
        except FileNotFoundError:
            print("⚠️ black not installed. Install with: pip install black")
            return subprocess.CompletedProcess([], 1)
    
    def check_imports(self):
        """Check import sorting."""
        print("📦 Checking import sorting...")
        
        try:
            cmd = [sys.executable, "-m", "isort", "--check-only", str(self.src_dir), str(self.test_dir)]
            return subprocess.run(cmd, cwd=self.project_root)
        except FileNotFoundError:
            print("⚠️ isort not installed. Install with: pip install isort")
            return subprocess.CompletedProcess([], 1)
    
    def install_test_dependencies(self):
        """Install testing dependencies."""
        print("📦 Installing test dependencies...")
        
        cmd = [
            sys.executable, "-m", "pip", "install",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "pytest-asyncio>=0.21.0"
        ]
        
        return subprocess.run(cmd, cwd=self.project_root)
    
    def clean_cache(self):
        """Clean pytest cache and coverage files."""
        print("🧹 Cleaning test cache...")
        
        import shutil
        
        # Remove pytest cache
        pytest_cache = self.project_root / ".pytest_cache"
        if pytest_cache.exists():
            shutil.rmtree(pytest_cache)
            print("   Removed .pytest_cache")
        
        # Remove coverage files
        coverage_files = [
            self.project_root / ".coverage",
            self.project_root / "coverage.xml",
            self.project_root / "htmlcov"
        ]
        
        for file_path in coverage_files:
            if file_path.exists():
                if file_path.is_file():
                    file_path.unlink()
                else:
                    shutil.rmtree(file_path)
                print(f"   Removed {file_path.name}")
        
        # Remove __pycache__ directories
        for pycache in self.project_root.rglob("__pycache__"):
            shutil.rmtree(pycache, ignore_errors=True)
        
        print("   Removed __pycache__ directories")


def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(description="Physical Security System Test Runner")
    
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--auth", action="store_true", help="Run authentication tests")
    parser.add_argument("--detection", action="store_true", help="Run detection tests")
    parser.add_argument("--security", action="store_true", help="Run security tests")
    parser.add_argument("--ui", action="store_true", help="Run UI tests")
    parser.add_argument("--utils", action="store_true", help="Run utility tests")
    parser.add_argument("--fast", action="store_true", help="Run fast tests only")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage report")
    parser.add_argument("--lint", action="store_true", help="Run code linting")
    parser.add_argument("--format", action="store_true", help="Format code")
    parser.add_argument("--imports", action="store_true", help="Check import sorting")
    parser.add_argument("--install-deps", action="store_true", help="Install test dependencies")
    parser.add_argument("--clean", action="store_true", help="Clean test cache")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    # Handle no arguments - show help
    if not any(vars(args).values()):
        parser.print_help()
        return 0
    
    exit_code = 0
    
    try:
        if args.install_deps:
            result = runner.install_test_dependencies()
            exit_code = max(exit_code, result.returncode)
        
        if args.clean:
            runner.clean_cache()
        
        if args.format:
            result = runner.format_code()
            exit_code = max(exit_code, result.returncode)
        
        if args.imports:
            result = runner.check_imports()
            exit_code = max(exit_code, result.returncode)
        
        if args.lint:
            result = runner.lint_code()
            exit_code = max(exit_code, result.returncode)
        
        if args.all:
            result = runner.run_all_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.unit:
            result = runner.run_unit_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.integration:
            result = runner.run_integration_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.auth:
            result = runner.run_auth_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.detection:
            result = runner.run_detection_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.security:
            result = runner.run_security_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.ui:
            result = runner.run_ui_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.utils:
            result = runner.run_utils_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.fast:
            result = runner.run_fast_tests()
            exit_code = max(exit_code, result.returncode)
        
        if args.coverage:
            result = runner.run_with_coverage_report()
            exit_code = max(exit_code, result.returncode)
        
    except KeyboardInterrupt:
        print("\n❌ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        return 1
    
    if exit_code == 0:
        print("\n✅ All operations completed successfully!")
    else:
        print(f"\n❌ Some operations failed (exit code: {exit_code})")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
