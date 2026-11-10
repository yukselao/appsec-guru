---
name: fetch_attachment
description: Fetch a WAS scan result attachment (screenshot, request/response capture) referenced by a finding.
parameters: {"type": "object", "properties": {"result_id": {"type": "string"}, "attachment_id": {"type": "string"}}, "required": ["result_id", "attachment_id"]}
agent_callable: false
---
Used when a finding references an attachment id. The harness downloads it through
GET /rest/scanResult/{id}/attachment/{attachmentID} and includes a short text
summary (type, size) in the analysis context; images are linked, not inlined.
