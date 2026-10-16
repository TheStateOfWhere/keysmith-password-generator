[{{- range $i, $result := . -}}
{{- if $i }},{{ end -}}
{{- $row := mustFromJson (mustToJson $result) -}}
{{- $_ := set $row "Packages" (default (list) $result.Packages) -}}
{{- $_ := set $row "Vulnerabilities" (default (list) $result.Vulnerabilities) -}}
{{- mustToJson $row -}}
{{- end -}}]
