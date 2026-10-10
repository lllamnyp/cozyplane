#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$(mktemp -d)
trap 'rm -rf -- "$output"' EXIT
cd "$root"
# Match the Kubernetes 0.35 API used by the repository. The generated body is
# wrapped in the chart's existing Helm condition, without editing the schema.
go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1 \
  crd paths=./api/localsdn/v1alpha1 output:crd:dir="$output"
template=chart/cozyplane/templates/crds.yaml
wrapper=$(sed -n '1,/{{- if .Values.crds.enabled }}/p' "$template")
{
  printf '%s\n' "$wrapper"
  cat "$output/local.sdn.cozystack.io_fabricips.yaml"
  printf '{{- end }}\n'
} > "$template"
