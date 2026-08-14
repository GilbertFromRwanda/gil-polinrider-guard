FROM python:3.12-slim

# unbuffer stdout/stderr -- without this, Python fully buffers output when
# there's no TTY (i.e. always, under Docker), so log lines like the web UI's
# startup hint sit unseen for as long as the process runs
ENV PYTHONUNBUFFERED=1

# git: needed for the git-date scanner and the surgical cleaner's mirror-clone workflow
# git-filter-repo: required by scripts/surgical_clean.py
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --root-user-action=ignore git-filter-repo

WORKDIR /app

COPY pyproject.toml README.md ./
COPY polinrider_guard/ ./polinrider_guard/
COPY scripts/ ./scripts/
COPY rules/ ./rules/

RUN pip install --no-cache-dir --root-user-action=ignore ".[web]"

# Mount the repo to scan at /scan, e.g.:
#   docker run --rm -v /path/to/repo:/scan polinrider-guard /scan
# Or run the web UI instead (paste a git URL, get a report):
#   docker run --rm -p 8765:8765 --entrypoint polinrider-guard-web polinrider-guard --host 0.0.0.0
WORKDIR /scan
EXPOSE 8765
ENTRYPOINT ["polinrider-guard"]
