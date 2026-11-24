#!/usr/bin/env bash
# sec-check workbench — เมนูโต้ตอบ · ใช้: ./sc
cd "$(dirname "$0")"
exec python3 workbench.py "$@"
