{{/*
Expand the name of the chart.
*/}}
{{- define "keystone-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "keystone-mcp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "keystone-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "keystone-mcp.labels" -}}
helm.sh/chart: {{ include "keystone-mcp.chart" . }}
{{ include "keystone-mcp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "keystone-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keystone-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "keystone-mcp.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}

{{- define "keystone-mcp.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "keystone-mcp.imageTag" .) }}
{{- end }}

{{- define "keystone-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keystone-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "keystone-mcp.secretName" -}}
{{- if .Values.secret.create }}
{{- include "keystone-mcp.fullname" . }}
{{- else }}
{{- required "existingSecret is required when secret.create is false" .Values.existingSecret }}
{{- end }}
{{- end }}

{{/*
SHA-256 of login-providers only — login providers are read at startup; policy
and upstream registry are hot-reloaded and must not trigger a rolling restart.
*/}}
{{- define "keystone-mcp.loginProvidersChecksum" -}}
{{- $providers := .Values.loginProviders | default "" | toString -}}
{{- $providers | sha256sum }}
{{- end }}

{{- define "keystone-mcp.baseUrlHost" -}}
{{- $parsed := urlParse .Values.baseUrl -}}
{{- $parsed.host }}
{{- end }}

{{- define "keystone-mcp.validate" -}}
{{- if not .Values.baseUrl }}
{{- fail "values.baseUrl is required (sets KEYSTONE_MCP_BASE_URL)" }}
{{- end }}
{{- if and (not .Values.existingSecret) (not .Values.secret.create) }}
{{- fail "set values.existingSecret to your Secret name, or secret.create: true for demo/kind only" }}
{{- end }}
{{- if and (eq .Values.rbac.policyTools "full") (not .Values.rbac.existingPolicyClaim) }}
{{- fail "rbac.policyTools \"full\" requires rbac.existingPolicyClaim (ReadWriteMany PVC with a writable policy file)" }}
{{- end }}
{{- if and (gt (int .Values.replicaCount) 1) (eq .Values.profile "local") (not .Values.postgresql.enabled) }}
{{- fail "replicaCount > 1 with profile \"local\" requires postgresql.enabled or an external Postgres URL in the Secret (SQLite is single-replica)" }}
{{- end }}
{{- if and .Values.ingress.enabled .Values.ingress.host }}
{{- $host := include "keystone-mcp.baseUrlHost" . }}
{{- if and $host (ne $host .Values.ingress.host) }}
{{- fail (printf "ingress.host (%s) must match the host in baseUrl (%s)" .Values.ingress.host $host) }}
{{- end }}
{{- end }}
{{- end }}
