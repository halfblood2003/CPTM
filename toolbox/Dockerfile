# CPTM Toolbox: fat image with curated cloud pentest tools.
#
# Key design points:
#  * Kali rolling ships Python 3.14, which breaks several pentest tools pinned to
#    older pydantic/pip. Tools that need it get their own Python 3.12 via `uv`,
#    so we are not at the mercy of the distro interpreter.
#  * Every tool that can be installed cleanly is installed hard (no `|| true`),
#    so the build fails loudly rather than silently shipping a broken image.
#    Only genuinely optional, non-essential extras are allowed to be skipped.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TERM=xterm-256color \
    PATH="/root/.local/bin:/usr/local/bin:/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    AWS_SHARED_CREDENTIALS_FILE=/creds/aws/credentials \
    AWS_CONFIG_FILE=/creds/aws/config \
    GOOGLE_APPLICATION_CREDENTIALS=/creds/gcp/sa.json

# ---- Core OS packages (all present in Kali repos) ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git python3 python3-pip python3-venv pipx \
      unzip jq zip nmap dnsutils whois netcat-traditional \
      golang build-essential graphviz \
      bash-completion less vim nano sudo \
    && rm -rf /var/lib/apt/lists/*

# ---- Optional OS packages (may not exist in every snapshot) ----
RUN apt-get update && apt-get install -y --no-install-recommends powershell \
    && rm -rf /var/lib/apt/lists/* || echo "powershell unavailable, skipping"

# ---- uv: gives us a managed Python 3.12 independent of the distro ----
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -sf /root/.local/bin/uv /usr/local/bin/uv \
    && uv python install 3.12 \
    && ln -sf "$(uv python find 3.12)" /usr/local/bin/python3.12

# Shared helper: create a uv venv on Python 3.12 and install packages into it.
# Usage: install_py <venv-name> <bin-name> <pip args...>
COPY install_py.sh /usr/local/bin/install_py.sh
RUN chmod +x /usr/local/bin/install_py.sh

# ---- Python 3.12 tools (version-sensitive) ----
RUN /usr/local/bin/install_py.sh prowler prowler prowler
RUN /usr/local/bin/install_py.sh scoutsuite scout scoutsuite
RUN /usr/local/bin/install_py.sh gcp-scanner gcp-scanner gcp-scanner
RUN /usr/local/bin/install_py.sh pacu pacu pacu
RUN /usr/local/bin/install_py.sh principalmapper pmapper principalmapper
# PMapper still uses `collections.Mapping` (removed in Python 3.10+). Run it on
# Python 3.9 and drop a sitecustomize shim into its venv so the legacy ABCs are
# importable again.
RUN uv venv --python 3.9 /opt/venvs/pmapper \
    && VIRTUAL_ENV=/opt/venvs/pmapper uv pip install --python /opt/venvs/pmapper/bin/python principalmapper \
    && SP="$(ls -d /opt/venvs/pmapper/lib/python3.*/site-packages | head -1)" \
    && printf 'import collections, collections.abc\nfor _n in ("Mapping", "MutableMapping", "Sequence", "Iterable", "Callable", "Set", "MutableSet", "Hashable"):\n    if not hasattr(collections, _n):\n        setattr(collections, _n, getattr(collections.abc, _n))\n' \
       > "$SP/sitecustomize.py" \
    && ln -sf /opt/venvs/pmapper/bin/pmapper /usr/local/bin/pmapper
RUN /usr/local/bin/install_py.sh roadrecon roadrecon roadrecon
RUN /usr/local/bin/install_py.sh kube-hunter kube-hunter kube-hunter
RUN /usr/local/bin/install_py.sh awsclic aws awscli
RUN python3 -m venv /opt/venvs/azcli \
    && /opt/venvs/azcli/bin/pip install --no-cache-dir azure-cli \
    && ln -sf /opt/venvs/azcli/bin/az /usr/local/bin/az

# ---- enumerate-iam (GitHub only; no packaging metadata upstream, so we clone
#      it and expose the script through a tiny launcher on PATH) ----
RUN python3 -m venv /opt/venvs/enumerate-iam \
    && /opt/venvs/enumerate-iam/bin/pip install --no-cache-dir boto3 botocore \
    && git clone --depth 1 https://github.com/andresriancho/enumerate-iam.git /opt/tools/enumerate-iam \
    && printf '#!/bin/sh\nexec /opt/venvs/enumerate-iam/bin/python /opt/tools/enumerate-iam/enumerate-iam.py "$@"\n' \
       > /usr/local/bin/enumerate-iam \
    && chmod +x /usr/local/bin/enumerate-iam

# ---- Go-based tools ----
RUN go install github.com/BishopFox/cloudfox@latest \
    && ln -sf /root/go/bin/cloudfox /usr/local/bin/cloudfox

# ---- cloud_enum (Python package; install from git so deps + entry point work) ----
RUN /usr/local/bin/install_py.sh cloud-enum cloud_enum \
    "git+https://github.com/initstring/cloud_enum.git"

# ---- CloudBrute (build from source; upstream moved to 0xsha/CloudBrute) ----
# Built in place as well as on PATH: CloudBrute loads config/ and modules/
# relative to its working directory, so the job runs it from the repo root.
RUN git clone --depth 1 https://github.com/0xsha/CloudBrute.git /opt/tools/CloudBrute \
    && cd /opt/tools/CloudBrute \
    && go build -o cloudbrute . \
    && cp cloudbrute /usr/local/bin/cloudbrute \
    && chmod +x /usr/local/bin/cloudbrute

# ---- MicroBurst (Azure PowerShell toolkit) ----
RUN git clone --depth 1 https://github.com/NetSPI/MicroBurst.git /opt/tools/MicroBurst || \
    echo "MicroBurst clone failed (optional, PowerShell-only tool)"

# ---- kubectl (not packaged in Kali) ----
# The k8s release CDN occasionally drops a connection mid-download; retry so a
# transient network blip doesn't fail the whole toolbox build.
RUN set -eux; \
    KVER=$(curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 https://dl.k8s.io/release/stable.txt); \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 -o /tmp/kubectl \
      "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl"; \
    install -m 0755 /tmp/kubectl /usr/local/bin/kubectl; \
    rm -f /tmp/kubectl

# ---- kube-bench (release asset names are versioned; resolve dynamically) ----
RUN set -eux; \
    KB_VER=$(curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
      https://api.github.com/repos/aquasecurity/kube-bench/releases/latest \
      | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4 | sed 's/^v//'); \
    echo "installing kube-bench ${KB_VER}"; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
      "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VER}/kube-bench_${KB_VER}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin kube-bench; \
    chmod +x /usr/local/bin/kube-bench

# ---- Trivy ----
RUN curl -sL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# Create the AZURE_CONFIG_DIR path so azure-cli never hits a read-only /creds
# when it tries to write a config profile at first use.
ENV AZURE_CONFIG_DIR=/root/.azure

WORKDIR /workspace
CMD ["sleep", "infinity"]
