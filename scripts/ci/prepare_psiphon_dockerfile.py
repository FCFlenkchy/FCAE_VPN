#!/usr/bin/env python3
import re
import sys
from pathlib import Path


def prepare(source: Path, destination: Path) -> None:
    dockerfile = source.read_text(encoding="utf-8")
    base = "FROM --platform=linux/amd64 ubuntu:18.04"
    start = "RUN apt-get update -y && apt-get install -y --no-install-recommends \\\n"
    end = "  && apt-get clean \\\n  && rm -rf /var/lib/apt/lists/*"
    if dockerfile.count(base) != 1 or dockerfile.count(start) != 1 or dockerfile.count(end) != 1:
        raise SystemExit("Pinned Psiphon Dockerfile changed; review its CI adaptation")

    begin = dockerfile.index(start)
    finish = dockerfile.index(end, begin)
    package_lines = dockerfile[begin + len(start):finish].splitlines()
    packages = []
    for line in package_lines:
        match = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9.+-]*)\s*\\\s*", line)
        if not match:
            raise SystemExit("Unexpected package list in pinned Psiphon Dockerfile")
        packages.append(match.group(1))
    if not packages or len(packages) != len(set(packages)):
        raise SystemExit("Invalid package list in pinned Psiphon Dockerfile")
    package_list = " ".join(packages)

    apt_step = f"""COPY .fcae-ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
RUN set -eu; \\
    success=0; \\
    for mirror in archive.ubuntu.com azure.archive.ubuntu.com us.archive.ubuntu.com; do \\
      echo \"Trying Ubuntu mirror $mirror\"; \\
      printf 'deb https://%s/ubuntu/ bionic main restricted universe multiverse\\ndeb https://%s/ubuntu/ bionic-updates main restricted universe multiverse\\ndeb https://%s/ubuntu/ bionic-security main restricted universe multiverse\\ndeb https://%s/ubuntu/ bionic-backports main restricted universe multiverse\\n' \"$mirror\" \"$mirror\" \"$mirror\" \"$mirror\" > /etc/apt/sources.list; \\
      rm -rf /var/lib/apt/lists/*; \\
      update_status=0; \\
      timeout 180s apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=20 update > /tmp/fcae-apt-update.log 2>&1 || update_status=$?; \\
      cat /tmp/fcae-apt-update.log; \\
      if [ \"$update_status\" -eq 0 ] && ! grep -Eq '^(Err:|E:|W:)' /tmp/fcae-apt-update.log; then \\
        if timeout 600s apt-get -o Acquire::Retries=2 -o Acquire::https::Timeout=20 install -y --no-install-recommends --download-only {package_list}; then \\
          success=1; break; \\
        fi; \\
      fi; \\
      echo \"Ubuntu mirror $mirror failed; trying the next mirror\" >&2; \\
    done; \\
    rm -f /tmp/fcae-apt-update.log; \\
    if [ \"$success\" -ne 1 ]; then echo 'All Ubuntu mirrors failed' >&2; exit 1; fi; \\
    apt-get install -y --no-install-recommends --no-download {package_list}; \\
    apt-get clean; \\
    rm -rf /var/lib/apt/lists/*"""

    dockerfile = dockerfile[:begin] + apt_step + dockerfile[finish + len(end):]
    dockerfile = dockerfile.replace(base, "FROM ubuntu:18.04", 1)
    destination.write_text(dockerfile, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: prepare_psiphon_dockerfile.py INPUT OUTPUT")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
