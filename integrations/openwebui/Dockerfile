# syntax=docker/dockerfile:1
#
# Open WebUI with rbic-plugin preinstalled, so the RBIC Pipe function
# (integrations/openwebui/rbic_pipe.py) can `import rbic` without any
# frontmatter pip install.
#
# Build from the REPOSITORY ROOT (the wheel is built from src/):
#   docker build -f integrations/openwebui/Dockerfile -t rbic-openwebui:dev .
# or `docker compose up --build` in integrations/openwebui/.
#
# Base: Open WebUI v0.12.4 (2026-10-25; carries security fixes over v0.12.3),
# pinned by digest. Bump tag and digest together, then re-check the facts
# listed in integrations/openwebui/README.md ("Verified against").
ARG OPENWEBUI_IMAGE=ghcr.io/open-webui/open-webui:v0.12.4@sha256:a5b9e403d19154796850679c8c5d1295301cee954be8b84ddd62af92426558f7

# ---- stage 1: build the rbic-plugin wheel (rbic-plugin is not on PyPI yet) --
FROM ${OPENWEBUI_IMAGE} AS wheel
WORKDIR /src
COPY integrations/openwebui/requirements-build.txt /tmp/requirements-build.txt
RUN python -m venv /opt/build-venv \
 && /opt/build-venv/bin/python -m pip install --no-cache-dir --require-hashes \
        -r /tmp/requirements-build.txt
COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/build-venv/bin/python -m build --wheel --no-isolation --outdir /dist

# ---- stage 2: Open WebUI + rbic ---------------------------------------------
FROM ${OPENWEBUI_IMAGE}

# Once rbic-plugin is released on PyPI, drop stage 1 and the wheel COPY/install
# below and install the release with hashes instead, e.g.:
#   ARG RBIC_VERSION=0.1.0
#   COPY integrations/openwebui/requirements-pypi.txt /tmp/
#   # requirements-pypi.txt: rbic-plugin==${RBIC_VERSION} --hash=sha256:<from PyPI>
#   RUN python -m pip install --no-cache-dir --no-deps --require-hashes \
#         -r /tmp/requirements-pypi.txt -r /tmp/requirements-rbic.txt
COPY integrations/openwebui/requirements-rbic.txt /tmp/requirements-rbic.txt
COPY --from=wheel /dist/ /tmp/rbic-dist/
RUN python -m pip install --no-cache-dir --no-deps --require-hashes \
        -r /tmp/requirements-rbic.txt \
 && python -m pip install --no-cache-dir --no-deps /tmp/rbic-dist/rbic_plugin-*.whl \
 && if python -m pip check 2>/dev/null | grep -i '^rbic-plugin '; then \
        echo "rbic-plugin's dependencies are not satisfied by this image" >&2; exit 1; \
    fi \
 && python -c "import anthropic, casbin, rbic, sqlglot; print('rbic', rbic.__version__, '| anthropic', anthropic.__version__, '| sqlglot', sqlglot.__version__)" \
 && rm -rf /tmp/rbic-dist /tmp/requirements-rbic.txt

# The Pipe file, for reference (admins import it via Admin Panel -> Functions).
COPY integrations/openwebui/rbic_pipe.py /app/rbic/rbic_pipe.py

# Never let a function's frontmatter pip-install packages into this image.
ENV ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS=false
