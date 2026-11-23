#!/usr/bin/env bash
# สแกนจากเทอร์มินัล — ใช้: ./scan.sh host | ./scan.sh lan | ./scan.sh web <url> ...
cd "$(dirname "$0")"
exec python3 seccheck.py "$@"
