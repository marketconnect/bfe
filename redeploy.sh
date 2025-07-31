#!/bin/bash
set -e

echo "=== GIT PULL ==="
git pull

echo "=== BUILD ==="
go build -o /usr/local/bin/bfe main.go

echo "=== SYSTEMD RESTART ==="
sudo systemctl restart bfe.service

echo "=== SHOW JOURNAL ==="
sudo journalctl -u bfe.service -n 50 --no-pager