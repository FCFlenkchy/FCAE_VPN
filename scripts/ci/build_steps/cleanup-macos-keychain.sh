#!/usr/bin/env bash
security delete-keychain "$RUNNER_TEMP/build.keychain-db" 2>/dev/null || true
