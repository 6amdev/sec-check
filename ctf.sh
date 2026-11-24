#!/usr/bin/env bash
# เปิดสนามเจาะ CTF — ใช้: ./ctf.sh  (เป้าฝึกบน localhost เท่านั้น)
cd "$(dirname "$0")"
exec python3 lab/ctf.py "$@"
