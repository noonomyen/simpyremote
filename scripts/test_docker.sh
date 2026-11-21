#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${SIMPYREMOTE_TEST_IMAGE:-simpyremote-test}"

if [[ "${1:-}" == "--build" ]]; then
    docker build -t "$IMAGE" -f "$ROOT/docker/Dockerfile.test" "$ROOT/docker"
fi

run_in_container() {
    local label="$1"
    local cmd="$2"
    echo "=== [$label] ==="
    docker run --rm \
        --network=none \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        -v "$ROOT:/src_ro:ro" \
        "$IMAGE" \
        bash -euo pipefail -c "
            mkdir -p /tmp/work_root
            cp -r /src_ro/src /src_ro/scripts /src_ro/tests /tmp/work_root/
            find /tmp/work_root -type d -name __pycache__ -exec rm -rf {} +
            cd /tmp/work_root
            $cmd
        "
}

run_in_container "Linux Python 3.14" \
    "uv run --offline --no-project --python 3.14.10 python -m unittest discover -s tests -v"

run_in_container "Linux Python 3.15" \
    "uv run --offline --no-project --python 3.15.2 python -m unittest discover -s tests -v"

run_in_container "Wine Windows Python 3.14" \
    "wine /opt/winpy314/tools/python.exe -m unittest discover -s tests -v && wineserver -w"

run_in_container "Wine Windows Python 3.15" \
    "wine /opt/winpy315/tools/python.exe -m unittest discover -s tests -v && wineserver -w"
