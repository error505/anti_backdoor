import pytest

from backdoor_watch.ai.settings_store import AiSettingsStore
from backdoor_watch.domain.ai import AiProvider
from backdoor_watch.domain.errors import ActionRefusedError


def test_defaults_when_nothing_saved(tmp_path):
    view = AiSettingsStore(tmp_path / "ai.json").view()
    assert (view.provider, view.model, view.effort, view.has_stored_key) == (AiProvider.ANTHROPIC, "claude-opus-5-5", "high", False)


def test_model_and_effort_are_remembered_per_provider(tmp_path):
    store = AiSettingsStore(tmp_path / "ai.json")
    store.save(AiProvider.ANTHROPIC, "claude-sonnet-5-5", "xhigh", None)
    store.save(AiProvider.OPENAI, "gpt-5-mini", "low", None)
    assert (store.view().model, store.view().effort) == ("gpt-5-mini", "low")
    store.save(AiProvider.ANTHROPIC, "claude-sonnet-5-5", "xhigh", None)
    assert (store.view().model, store.view().effort) == ("claude-sonnet-5-5", "xhigh")


def test_rejects_effort_the_provider_does_not_support(tmp_path):
    with pytest.raises(ActionRefusedError):
        AiSettingsStore(tmp_path / "ai.json").save(AiProvider.OPENAI, "gpt-5", "max", None)


def test_api_key_is_encrypted_on_disk_and_hidden_from_view(tmp_path):
    path = tmp_path / "ai.json"
    store = AiSettingsStore(path)
    store.save(AiProvider.ANTHROPIC, None, None, "sk-ant-secret-value-1234")
    assert "sk-ant-secret" not in path.read_text(encoding="utf-8")
    assert store.view().key_hint == "…1234"
    assert store.credentials().api_key == "sk-ant-secret-value-1234"
