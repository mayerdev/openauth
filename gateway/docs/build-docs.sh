#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

npx @redocly/cli build-docs "$SCRIPT_DIR/openapi.yml" --output "$SCRIPT_DIR/index.html"
