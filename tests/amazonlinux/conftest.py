import pytest

import testinfra
import subprocess
import os

root_dir = os.path.abspath(os.curdir)
base_image = os.getenv("IMAGE_NAME", "wazuh-agent-amazonlinux")
docker_file = os.getenv("DOCKERFILE", "images/Dockerfile.amazonlinux")
wazuh_agent_version = os.getenv("AGENT_VERSION", "4.3.10-1")


@pytest.fixture(scope="session")
def host(request):
    print(f"{root_dir}/images/Dockerfile.amazonlinux")
    subprocess.check_call(
        [
            "docker",
            "build",
            "-t",
            f"{base_image}",
            "-f",
            docker_file,
            "--build-arg",
            f"AGENT_VERSION={wazuh_agent_version}",
            root_dir,
        ]
    )
    docker_id = (
        subprocess.check_output(
            [
                "docker",
                "run",
                "-d",
                "--entrypoint",
                "sleep",
                f"{base_image}",
                "infinity",
            ]
        )
        .decode()
        .strip()
    )
    yield testinfra.get_host("docker://" + docker_id)

    print("Destroy container: " + docker_id)
    subprocess.call(["docker", "kill", docker_id])
