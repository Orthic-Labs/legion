import pathlib
import zipfile


def get_requires_for_build_wheel(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "fixture_pkg-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, "w") as wheel:
        wheel.writestr("fixture_pkg/__init__.py", "def answer(): return 42\n")
        wheel.writestr("fixture_pkg-1.0.0.dist-info/METADATA", "Metadata-Version: 2.4\nName: fixture-pkg\nVersion: 1.0.0\n")
        wheel.writestr("fixture_pkg-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        wheel.writestr("fixture_pkg-1.0.0.dist-info/RECORD", "fixture_pkg/__init__.py,sha256=invalid,0\n")
    return name
