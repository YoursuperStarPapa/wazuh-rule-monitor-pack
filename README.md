# Wazuh Rule & Monitor Creator — Portable Skill Pack

A reusable prompt/skill for generating Wazuh 4.14.5 XML detection rules and dashboard monitor configurations.

## What's Included

```
wazuh-rule-monitor-pack/
├── system-prompt.md          # Main skill — paste into any AI tool
├── examples/
│   └── sudo-auth-file-access.md   # Example input → output
└── README.md                 # This file
```

## How to Use

### ChatGPT / Claude / Gemini / Other AI
1. Open `system-prompt.md`
2. Copy everything below the `---` line into your AI tool's **system prompt** or **custom instructions**
3. Send your rule request:
   ```
   Rule name: Brute Force SSH Login
   Logic: process.name:sshd and match:"Failed password" and count > 5 in 60s
   ```

### Cursor / Windsurf / Code Assistants
1. Add `system-prompt.md` as a project rules file or `.cursorrules`
2. Ask the AI to generate rules in your project context

### OpenClaw
Already installed as a native skill. Just say:
> "Create wazuh rule: [name] with logic: [detection logic]"

## Input Format

Provide:
- **Rule name** — descriptive name for the rule
- **Detection logic** — what to match (process names, field patterns, thresholds)

Optional:
- Rule ID (default: auto-suggest from 100000-129999)
- Severity level (default: auto-suggest based on threat)

## Output

1. **Wazuh 4.14.5 XML rule** — ready to deploy
2. **Monitor & alert config guide** — dashboard, email, active response, testing

## Requirements

- Wazuh 4.14.5 (syntax may differ for other versions)
- Access to `/var/ossec/etc/rules/` on your Wazuh manager
