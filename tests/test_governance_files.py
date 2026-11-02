import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_license_is_declared_and_shipped():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in text
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert metadata["license"] == "MIT"
    assert metadata["license-files"] == ["LICENSE"]


def test_security_contributing_and_ownership_are_linked():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in ("SECURITY.md", "CONTRIBUTING.md", "docs/PROVENANCE.md"):
        assert f"]({target})" in readme
    assert (ROOT / "SECURITY.md").is_file()
    assert "@groktopus" in (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
