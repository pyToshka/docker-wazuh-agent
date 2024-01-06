import pytest


@pytest.mark.parametrize(
    "srv_folders",
    ["/var/ossec", "/var/ossec/wodles", "/var/ossec/ruleset", "/var/ossec/etc"],
)
def test_folders(host, srv_folders):
    folders = host.file(srv_folders)
    assert folders.is_directory
    assert folders.user == "wazuh"
    assert folders.group == "wazuh"


def test_python_version(host):
    python = host.package("python3")
    assert python.is_installed
    assert python.version.startswith("3.11")


@pytest.mark.parametrize(
    "name",
    [
        "bash",
        "ca-certificates",
        "curl",
        "procps",
        "python3",
        "tzdata",
        "python3-docker",
        "wazuh-agent",
        "apt-transport-https",
        "gnupg2",
        "inotify-tools",
        "python3-setuptools",
        "python3-pip",
    ],
)
def test_base_pkgs(host, name):
    pkg = host.package(name)
    assert pkg.is_installed


def test_wazuh_agent_script(host):
    folders = host.file("/var/ossec/register_agent.py")
    assert folders.user == "wazuh"
    assert folders.group == "wazuh"
