#!/bin/bash
set -e

echo "[post-merge] Running npm install..."
npm install --no-audit --no-fund 2>&1 | tail -5
echo "[post-merge] Done"
