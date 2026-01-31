#!/usr/bin/env bash
set -euo pipefail

swift package plugin --allow-writing-to-package-directory swiftformat --lint

swift test
