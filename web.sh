#!/usr/bin/env bash
# เปิดหน้าเว็บ sec-check — ใช้: ./web.sh [--host 0.0.0.0] [--pin 1234]  (ไม่ต้องใช้ sudo)
cd "$(dirname "$0")"
exec python3 webapp.py "$@"
