{{/* Chart name, truncated to the 63 characters a DNS label allows. */}}
{{- define "dilion.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. The "-metrics" suffix still has to fit in 63
characters, hence 55.
*/}}
{{- define "dilion.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 55 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 55 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 55 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "dilion.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dilion.labels" -}}
helm.sh/chart: {{ include "dilion.chart" . }}
{{ include "dilion.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "dilion.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dilion.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "dilion.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dilion.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dilion.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/* Name of the Secret the pods read their env from. */}}
{{- define "dilion.secretName" -}}
{{- default (include "dilion.fullname" .) .Values.secrets.existingSecret }}
{{- end }}

{{/*
Refuse to render a chart-managed Secret that lacks what must survive restarts.
An existing Secret is the operator's responsibility and is not inspected.
*/}}
{{- define "dilion.validateSecrets" -}}
{{- if not .Values.secrets.existingSecret }}
{{- if not .Values.secrets.dsn }}
{{- fail "secrets.dsn is required (or set secrets.existingSecret with a DILION_DSN key)" }}
{{- end }}
{{- if not .Values.secrets.masterKey }}
{{- fail "secrets.masterKey is required: without it every pod generates its own and stored PII is unreadable after a restart. Generate one with: head -c32 /dev/urandom | base64" }}
{{- end }}
{{- if not (or .Values.secrets.jwtSecret .Values.secrets.jwtKeys) }}
{{- fail "secrets.jwtSecret or secrets.jwtKeys is required: without one every pod signs tokens with its own ephemeral key" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Whether a ConfigMap of files (policy, PII fields) is needed. */}}
{{- define "dilion.hasFiles" -}}
{{- if or .Values.policy .Values.piiFields }}true{{ end }}
{{- end }}
