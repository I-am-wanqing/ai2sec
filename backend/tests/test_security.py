import io
import zipfile
from pathlib import Path

import pytest

from ai2sec_backend.config import Settings
from ai2sec_backend.sandbox import DockerSandbox, SandboxPolicyError
from ai2sec_backend.security import normalize_public_url, safe_extract_archive


def test_rejects_private_and_metadata_targets() -> None:
    settings = Settings(database_url="sqlite:///:memory:")
    for url in [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data",
        "http://192.168.1.10",
    ]:
        with pytest.raises(ValueError):
            normalize_public_url(url, settings)


def test_accepts_public_http_url() -> None:
    settings = Settings(database_url="sqlite:///:memory:")
    assert normalize_public_url("https://example.com/path#frag", settings) == "https://example.com/path"


def test_safe_extract_rejects_zip_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../evil.py", "print('nope')")

    with pytest.raises(ValueError):
        safe_extract_archive(archive_path, tmp_path / "out")


def test_safe_extract_accepts_normal_zip(tmp_path: Path) -> None:
    archive_path = tmp_path / "source.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("app/main.py", "print('ok')")

    files = safe_extract_archive(archive_path, tmp_path / "out")
    assert files
    assert (tmp_path / "out" / "app" / "main.py").exists()


def test_sandbox_rejects_non_allowlisted_command() -> None:
    sandbox = DockerSandbox()
    with pytest.raises(SandboxPolicyError):
        sandbox.run_terminal("terminal", ["sh", "-c", "id"])
