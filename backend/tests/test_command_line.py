import os

from backdoor_watch.domain.command_line import extract_image_path


def test_quoted_executable_with_arguments():
    assert extract_image_path(r'"C:\Program Files\App\app.exe" --start') == r"C:\Program Files\App\app.exe"


def test_unquoted_path_with_spaces_stops_at_executable_suffix():
    command = r"C:\Program Files\Some App\tool.exe -k netsvcs"
    assert extract_image_path(command) == r"C:\Program Files\Some App\tool.exe"


def test_service_systemroot_prefix_is_resolved():
    resolved = extract_image_path(r"\SystemRoot\System32\drivers\foo.sys")
    assert resolved.lower() == os.path.join(os.environ["SystemRoot"], r"System32\drivers\foo.sys").lower()


def test_bare_system_tool_resolves_to_system32():
    resolved = extract_image_path("sc.exe config upnphost start= auto")
    assert resolved.lower().endswith(r"system32\sc.exe")


def test_empty_command_has_no_image():
    assert extract_image_path("   ") is None
