#!/usr/bin/env bash
set -euo pipefail

make -C "$(cd "$(dirname "$0")/.." && pwd)" pdf
