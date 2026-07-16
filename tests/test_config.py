from __future__ import annotations

import errno
from pathlib import Path

import pytest

from vulnnote_manager.config import (
    ConfigurationError,
    Settings,
    get_openai_api_key,
    load_settings,
    prepare_data_directories,
    resolve_default_data_dir,
)
from vulnnote_manager.storage import translate_storage_error


def test_linux_default_data_dir_uses_xdg() -> None:
    path = resolve_default_data_dir(
        system="Linux", environ={"XDG_DATA_HOME": "/var/example"}, home=Path("/home/test")
    )
    assert path == Path("/var/example/vulnnote-manager")


def test_linux_default_data_dir_falls_back_to_home() -> None:
    path = resolve_default_data_dir(system="Linux", environ={}, home=Path("/home/test"))
    assert path == Path("/home/test/.local/share/vulnnote-manager")


def test_macos_default_data_dir() -> None:
    path = resolve_default_data_dir(system="Darwin", environ={}, home=Path("/Users/test"))
    assert path == Path("/Users/test/Library/Application Support/VulnNote Manager")


def test_windows_default_data_dir() -> None:
    path = resolve_default_data_dir(
        system="Windows", environ={"LOCALAPPDATA": "C:/Users/test/AppData/Local"}, home=Path("C:/Users/test")
    )
    assert path == Path("C:/Users/test/AppData/Local/VulnNote Manager")


def test_load_settings_reads_supported_environment_values(tmp_path: Path) -> None:
    settings = load_settings(
        {
            "VULNNOTE_HOST": "127.0.0.2",
            "VULNNOTE_PORT": "8765",
            "VULNNOTE_DATA_DIR": str(tmp_path),
            "OPENAI_MODEL": "model-for-test",
            "VULNNOTE_AI_TIMEOUT": "12.5",
            "VULNNOTE_PAGE_SIZE": "50",
        }
    )
    assert settings.host == "127.0.0.2"
    assert settings.port == 8765
    assert settings.data_dir == tmp_path
    assert settings.openai_model == "model-for-test"
    assert settings.ai_timeout_seconds == 12.5
    assert settings.page_size == 50


def test_relative_data_dir_is_resolved_to_an_absolute_path() -> None:
    settings = load_settings({"VULNNOTE_DATA_DIR": "relative-data"})
    assert settings.data_dir.is_absolute()
    assert settings.data_dir.name == "relative-data"


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("VULNNOTE_PORT", "not-a-number", "整数"),
        ("VULNNOTE_PORT", "70000", "範囲"),
        ("VULNNOTE_AI_TIMEOUT", "0", "範囲"),
        ("VULNNOTE_PAGE_SIZE", "30", "25、50、100"),
        ("OPENAI_MODEL", " ", "空"),
    ],
)
def test_load_settings_rejects_invalid_values(name: str, value: str, expected: str) -> None:
    with pytest.raises(ConfigurationError, match=expected):
        load_settings({name: value})


def test_prepare_data_directories_creates_required_directories(settings: Settings) -> None:
    prepare_data_directories(settings)
    assert settings.data_dir.is_dir()
    assert settings.upload_dir.is_dir()
    assert settings.recovery_dir.is_dir()


def test_prepare_data_directories_rejects_file_as_data_dir(tmp_path: Path) -> None:
    data_path = tmp_path / "data"
    data_path.write_text("not a directory", encoding="utf-8")
    settings = Settings(
        host="127.0.0.1",
        port=5000,
        data_dir=data_path,
        openai_model="test-model",
        ai_timeout_seconds=2,
        page_size=25,
    )
    with pytest.raises(ConfigurationError, match="VULNNOTE_DATA_DIR"):
        prepare_data_directories(settings)


def test_api_key_is_only_read_on_demand_and_hidden_from_settings_repr(tmp_path: Path) -> None:
    secret = "sk-test-secret"
    settings = load_settings({"VULNNOTE_DATA_DIR": str(tmp_path), "OPENAI_API_KEY": secret})
    assert get_openai_api_key({"OPENAI_API_KEY": secret}) == secret
    assert secret not in repr(settings)
    assert not hasattr(settings, "openai_api_key")


def test_storage_full_error_explains_cause_without_path() -> None:
    original = OSError(errno.ENOSPC, "secret/path/note-body")
    translated = translate_storage_error(original, operation="画像を保存")
    assert "空き容量" in str(translated)
    assert "secret/path" not in str(translated)
    assert translated.data_saved is False
