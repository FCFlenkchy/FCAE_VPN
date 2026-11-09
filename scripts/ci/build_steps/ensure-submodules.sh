#!/usr/bin/env bash
git submodule sync --recursive
git submodule update --init --recursive --depth 1
