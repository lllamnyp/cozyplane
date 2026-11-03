{{/* Common metadata labels (not used as selectors — selectors stay stable). */}}
{{- define "cozyplane.labels" -}}
app.kubernetes.io/name: cozyplane
app.kubernetes.io/part-of: cozyplane
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "cozyplane-%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/* imagePullSecrets block, rendered only when set. Call with the root context. */}}
{{- define "cozyplane.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* orgGateway env (internal/orggateway.FromEnv) for the agent, the responder
     and the controller; empty while disabled. Call with the root context. */}}
{{- define "cozyplane.orgGatewayEnv" -}}
{{- with .Values.orgGateway }}
{{- if .enabled }}
{{- range .addressCIDRs }}
{{- if not (has . $.Values.egress.internalCIDRs) }}
{{- fail (printf "orgGateway.addressCIDRs %s must also be listed in egress.internalCIDRs" .) }}
{{- end }}
{{- end }}
{{- $selector := list }}
{{- range $k, $v := .serviceSelector }}
{{- $selector = append $selector (printf "%s=%s" $k $v) }}
{{- end }}
- name: COZYPLANE_ORG_GATEWAY
  value: "true"
- name: COZYPLANE_ORG_GATEWAY_NAMESPACE_LABEL
  value: {{ .gatewayNamespaceLabel | quote }}
- name: COZYPLANE_ORG_GATEWAY_APEX_LABEL
  value: {{ .apexLabel | quote }}
- name: COZYPLANE_ORG_GATEWAY_SERVICE_SELECTOR
  value: {{ join "," $selector | quote }}
- name: COZYPLANE_ORG_GATEWAY_CIDRS
  value: {{ join "," .addressCIDRs | quote }}
- name: COZYPLANE_ORG_GATEWAY_APEX_SUFFIXES
  value: {{ join "," .apexSuffixes | quote }}
- name: COZYPLANE_ORG_GATEWAY_VPN_DNS
  value: {{ .vpnDNS | toString | quote }}
{{- end }}
{{- end }}
{{- end -}}
