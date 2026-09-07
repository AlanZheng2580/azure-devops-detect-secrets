#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  *Username*) printf '%s\n' "azure-pipelines" ;;
  *Password*) printf '%s\n' "${AZURE_DEVOPS_PAT:?AZURE_DEVOPS_PAT is required}" ;;
  *) exit 1 ;;
esac
