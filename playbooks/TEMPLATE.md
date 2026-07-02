# Playbook template

This file is Markdown so PenPal will not load it as a real playbook. Copy the JSON block into `playbooks/<your-playbook-id>.json`, then replace the placeholders.

```json
{
  "schema": "penpal-playbook-v1",
  "id": "service-to-next-check",
  "title": "Service to next focused check",
  "description": "Explain the high-probability enumeration path and what it may reveal.",
  "tags": [
    "service-name",
    "enumeration"
  ],
  "source_tier": "methodology",
  "sources": [
    {
      "title": "Source title",
      "type": "official",
      "url": "https://example.com"
    },
    {
      "title": "User note title",
      "type": "internal_note"
    }
  ],
  "review_status": "draft",
  "signals": [
    {
      "type": "service",
      "protocol": "tcp",
      "port": 1234
    },
    {
      "type": "evidence",
      "evidence_type": "username"
    }
  ],
  "actions": [
    {
      "id": "review-known-facts",
      "description": "Review the evidence that made this path worth checking.",
      "risk": "passive",
      "commands": [
        "python -m penpal evidence <target_name>",
        "python -m penpal suggest <target_name>"
      ]
    },
    {
      "id": "run-focused-enumeration",
      "description": "Run a visible, in-scope enumeration command and feed the output back into PenPal.",
      "risk": "normal",
      "commands": [
        "example-enum --host <target_host>",
        "python -m penpal ingest <target_name> --file ./example-enum.txt --source example-enum --service tcp/1234"
      ]
    }
  ],
  "safety": {
    "authorized_use_only": true,
    "requires_operator_approval": true
  }
}
```

Before opening a PR:

```bash
python -m penpal playbooks playbooks
python -m penpal playbooks playbooks --show service-to-next-check
python -m unittest discover -v
```
