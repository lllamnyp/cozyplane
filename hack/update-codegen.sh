#!/usr/bin/env bash

# Copyright 2026 The Cozyplane Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
# Resolve the code-generator module directory from the module graph so the
# version stays pinned by go.mod rather than hardcoded here.
if [[ -z "${CODEGEN_PKG:-}" ]]; then
    (cd "${SCRIPT_ROOT}" && go mod download k8s.io/code-generator)
    CODEGEN_PKG=$(cd "${SCRIPT_ROOT}" && go list -m -f '{{.Dir}}' k8s.io/code-generator)
fi

source "${CODEGEN_PKG}/kube_codegen.sh"

THIS_PKG="github.com/lllamnyp/cozyplane"

# List of API groups to generate code for. Add more here as they are added.
if [[ -n ${API_GROUPS+x} ]]; then
    read -r -a API_GROUPS <<<"$API_GROUPS"
else
    API_GROUPS=("sdn" "localsdn")
fi

# Generate helper code (deepcopy, defaulter, conversion).
for api_group in "${API_GROUPS[@]}"; do
    echo "Generating helper code for API group: ${api_group}"
    kube::codegen::gen_helpers \
        --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
        "${SCRIPT_ROOT}/api/${api_group}"

    # gen_helpers defaults to unsafe casts for layout-compatible structs.
    # Regenerate conversions without unsafe pointer reinterpretation. This
    # remains a conversion contract, not a deep-copy contract for all fields.
    if [[ "${api_group}" == "sdn" ]]; then
        rm "${SCRIPT_ROOT}/api/sdn/v1alpha1/zz_generated.conversion.go"
        (cd "${SCRIPT_ROOT}" && go run k8s.io/code-generator/cmd/conversion-gen \
            --skip-unsafe \
            --output-file zz_generated.conversion.go \
            --go-header-file hack/boilerplate.go.txt \
            "${THIS_PKG}/api/sdn/v1alpha1")
    fi
done

# Extra upstream packages needed for OpenAPI definitions referenced by our types.
OPENAPI_EXTRA_PKGS=(
    "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/version"
)

OPENAPI_EXTRA_PKGS_FLAGS=()
for pkg in "${OPENAPI_EXTRA_PKGS[@]}"; do
    OPENAPI_EXTRA_PKGS_FLAGS+=("--extra-pkgs" "${pkg}")
done

# Generate OpenAPI and client code for each API group.
for api_group in "${API_GROUPS[@]}"; do
    # OpenAPI definitions are only consumed by the aggregated apiserver. A
    # CRD-served group (localsdn) publishes its schema from the CRD itself.
    if [[ "${api_group}" == "localsdn" ]]; then
        echo "Skipping OpenAPI for CRD-served API group: ${api_group}"
    else
    echo "Generating OpenAPI for API group: ${api_group}"
    kube::codegen::gen_openapi \
        "${OPENAPI_EXTRA_PKGS_FLAGS[@]}" \
        --output-dir "${SCRIPT_ROOT}/pkg/generated/${api_group}/openapi" \
        --output-pkg "${THIS_PKG}/pkg/generated/${api_group}/openapi" \
        --report-filename "${SCRIPT_ROOT}/hack/api-rule-violations.report" \
        --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
        "${SCRIPT_ROOT}/api/${api_group}"
    fi

    echo "Generating client code for API group: ${api_group}"
    kube::codegen::gen_client \
        --one-input-api "${api_group}" \
        --with-watch \
        --with-applyconfig \
        --output-dir "${SCRIPT_ROOT}/pkg/generated/${api_group}" \
        --output-pkg "${THIS_PKG}/pkg/generated/${api_group}" \
        --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
        "${SCRIPT_ROOT}/api"

    # InformerFor accepts a caller-provided constructor. A started informer
    # cannot accept a transform; its error must not be silently discarded.
    factory="${SCRIPT_ROOT}/pkg/generated/${api_group}/informers/externalversions/factory.go"
    awk '
      /^[[:space:]]*informer.SetTransform\(f.transform\)$/ {
        print "\tif err := informer.SetTransform(f.transform); err != nil {"
        print "\t\tpanic(err)"
        print "\t}"
        replaced++; next
      }
      { print }
      END { if (replaced != 1) exit 1 }
    ' "${factory}" > "${factory}.tmp"
    mv "${factory}.tmp" "${factory}"
    gofmt -w "${factory}"

    echo "Completed code generation for API group: ${api_group}"
done

# Structural tenant schemas and their chart payload have a single generator.
# Pin the build-time tool separately from the runtime dependency graph.
if [[ " ${API_GROUPS[*]} " == *" sdn "* ]]; then
    (cd "${SCRIPT_ROOT}" && go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0 \
        crd paths=./api/sdn/v1alpha1 output:crd:dir=config/tenant-crd)
    mkdir -p "${SCRIPT_ROOT}/chart/cozyplane/files/tenant-crd"
    cp "${SCRIPT_ROOT}"/config/tenant-crd/*.yaml "${SCRIPT_ROOT}/chart/cozyplane/files/tenant-crd/"
fi

echo "Code generation complete for all API groups: ${API_GROUPS[*]}"
