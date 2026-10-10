#!/bin/bash
# install_py <venv-name> <bin-name> <pip args...>
# Creates a uv-managed Python 3.12 venv at /opt/venvs/<venv-name>, installs the
# given package(s), and links the resulting executable into /usr/local/bin.
set -euo pipefail

VENV_NAME="$1"
BIN_NAME="$2"
shift 2

uv venv --python 3.12 "/opt/venvs/${VENV_NAME}"
VIRTUAL_ENV="/opt/venvs/${VENV_NAME}" uv pip install --python "/opt/venvs/${VENV_NAME}/bin/python" "$@"
ln -sf "/opt/venvs/${VENV_NAME}/bin/${BIN_NAME}" "/usr/local/bin/${BIN_NAME}"

echo "installed ${BIN_NAME} from venv ${VENV_NAME}"
