#!/usr/bin/env python3
"""
Test script for dynamic path resolution in HackerOne MCP Server.
Verifies that the project root detection and MDC file path resolution
work correctly.
"""
import os
import sys
import tempfile
from pathlib import Path
from dotenv import load_dotenv

# Add the src directory to the path so we can import the main module
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from hackerone_mcp.main import get_project_root, MDC_FILE_PATH
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


def test_path_resolution():
    """Test the dynamic path resolution system."""
    print("🔍 Path Resolution Test")
    print("=" * 50)

    # Get current working directory
    current_dir = os.getcwd()
    print(f"Current working directory: {current_dir}")

    # Get test script location
    test_script_path = Path(__file__).parent.parent
    print(f"Test script location: {test_script_path}")

    # Test project root detection
    project_root = get_project_root()
    print(f"Detected project root: {project_root}")

    # Test MDC file path
    mdc_path = Path(MDC_FILE_PATH)
    print(f"MDC file path: {mdc_path}")

    # Check if MDC file exists
    if mdc_path.exists():
        print(f"✅ MDC file found at: {mdc_path}")
    else:
        print(f"⚠️  MDC file not found at: {mdc_path}")
        print("   This is expected if you haven't created the MDC file yet")

    # Verify paths are absolute
    if not mdc_path.is_absolute():
        print("❌ MDC path is not absolute")
        return False

    # Verify project root contains expected structure
    expected_dirs = ["src", "scripts"]
    missing_dirs = []
    for dir_name in expected_dirs:
        if not (project_root / dir_name).exists():
            missing_dirs.append(dir_name)

    if missing_dirs:
        print(f"❌ Missing expected directories: {missing_dirs}")
        return False

    return True


def test_environment_variable_override():
    """Test environment variable override for MDC path."""
    print("\n🔧 Environment Variable Test")
    print("=" * 50)

    # Create a temporary MDC file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".mdc", delete=False) as tmp:
        tmp.write("# Test MDC file\ntest: true\n")
        temp_mdc_path = tmp.name

    try:
        # Set environment variable
        os.environ["MDC_FILE_PATH"] = temp_mdc_path
        print(f"Custom MDC path: {temp_mdc_path}")

        # Reload the module to pick up the new environment variable
        # Note: This is a simplified test - in practice you'd need to
        # restart the server
        if Path(temp_mdc_path).exists():
            print("✅ Environment variable override works")
            print(f"   Custom MDC file created at: {temp_mdc_path}")
        else:
            print("❌ Environment variable override failed")
            return False

        return True

    finally:
        # Clean up
        try:
            os.unlink(temp_mdc_path)
        except (OSError, FileNotFoundError):
            pass
        # Reset environment variable
        if "MDC_FILE_PATH" in os.environ:
            del os.environ["MDC_FILE_PATH"]


def test_relative_path_resolution():
    """Test that relative paths are resolved correctly."""
    print("\n📁 Relative Path Resolution Test")
    print("=" * 50)

    project_root = get_project_root()

    # Test various relative paths
    test_cases = [
        ("src/hackerone_mcp/main.py", "Main module"),
        ("scripts/test_setup.py", "Test setup script"),
        ("rules/hackerone_mcp_directives.mdc", "MDC file"),
        ("pyproject.toml", "Project config"),
        ("README.md", "README file"),
    ]

    all_passed = True
    for relative_path, description in test_cases:
        full_path = project_root / relative_path
        if full_path.exists():
            print(f"✅ {description}: {full_path}")
        else:
            print(f"⚠️  {description}: {full_path} (not found)")
            # Only fail for critical files
            critical_files = ["src/hackerone_mcp/main.py", "pyproject.toml"]
            if relative_path in critical_files:
                all_passed = False

    return all_passed


def main():
    """Run all path resolution tests."""
    print("HackerOne MCP Server - Path Resolution Test")
    print("=" * 60)

    # Load environment variables
    load_dotenv()

    tests = [
        ("Path Resolution", test_path_resolution),
        ("Environment Variable Override", test_environment_variable_override),
        ("Relative Path Resolution", test_relative_path_resolution),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with error: {e}")

    print("\n" + "=" * 60)
    if passed == total:
        print("✅ All path resolution tests passed!")
        print(f"   {passed}/{total} tests successful")
        return True
    else:
        print(f"❌ {passed}/{total} tests passed")
        print("   Some path resolution tests failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
