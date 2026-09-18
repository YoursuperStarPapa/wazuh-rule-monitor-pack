# Example: Linux Sensitive Authentication File Access via Sudo

## User Input
- **Rule name:** Linux Sensitive Authentication File Access via Sudo
- **Logic:** process.name:sudo and dissect.content:*COMMAND=* and dissect.content:(*/etc/shadow* or */etc/passwd* or */etc/gshadow*)

---

## Section 1: XML Rule

```xml
<rule id="100001" level="12">
  <if_sid>0</if_sid>
  <field name="process.name" type="pcre2">^sudo$</field>
  <field name="dissect.content" type="pcre2">COMMAND=.*(/etc/shadow|/etc/passwd|/etc/gshadow)</field>
  <description>Sensitive Authentication File Access via Sudo</description>
  <mitre><id>T1003</id></mitre>
</rule>
```

---

## Section 2: Monitor & Alert Config

### ① Verify Rule Loaded
- Navigate: **Wazuh Dashboard → Management → Rules**
- Search: `100001` or `Sensitive Authentication`
- Confirm rule is present and enabled

### ② Create Monitor
- Navigate: **Wazuh Dashboard → OpenSearch Plugins → Alerting → Monitors → Create monitor**
- **Monitor name:** `Linux Sensitive Auth File Access via Sudo`
- **Index:** `wazuh-alerts-*`
- **Schedule:** Every 1 minute (or per your SOC cadence)

### ③ Extraction Query (Query DSL Editor)

Select **Extraction query editor** (not visual editor) and paste:

```json
{
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "rule.id": "100001"
          }
        },
        {
          "regexp": {
            "process.name": "sudo"
          }
        },
        {
          "regexp": {
            "dissect.content": "COMMAND=.*(/etc/shadow|/etc/passwd|/etc/gshadow)"
          }
        }
      ]
    }
  }
}
```

**Field mapping reference:**
| XML Rule Field | Query DSL Clause | Rationale |
|---|---|---|
| `<field name="process.name" type="pcre2">^sudo$</field>` | `{"regexp":{"process.name":"sudo"}}` | Positive match |
| `<field name="dissect.content" type="pcre2">COMMAND=.*shadow...</field>` | `{"regexp":{"dissect.content":"COMMAND=.*(/etc/shadow\|/etc/passwd\|/etc/gshadow)"}}` | OR via regex alternation |
| (no negate in this rule) | If negate: move to `must_not` array | Negate fields go in `must_not` |

### ④ Trigger Condition
- **Condition type:** Per monitor
- **Threshold expression:**
```
ctx.results[0].hits.total.value > 0
```
- **Action name:** `Sensitive auth file access detected`

### ⑤ Action Configuration

**Email action template:**
```
Subject: [Wazuh Alert] Sensitive Auth File Access via Sudo - Rule 100001

Body:
Monitor {{ctx.monitor.name}} triggered.

Alert: {{ctx.trigger.name}}
Severity: Level 12 (High)
Time: {{ctx.periodStart}}

Matching alerts:
{{#ctx.results[0].hits.hits}}
- Agent: {{_source.agent.name}} | User: {{_source.data.user.name}} | Command: {{_source.data.dissect.content}}
{{/ctx.results[0].hits.hits}}

MITRE: T1003 - Credential Access
```

**Webhook action template (JSON):**
```json
{
  "monitor": "{{ctx.monitor.name}}",
  "trigger": "{{ctx.trigger.name}}",
  "rule_id": "100001",
  "severity": "12",
  "time": "{{ctx.periodStart}}",
  "hits": "{{ctx.results[0].hits.total.value}}"
}
```

### ⑥ ossec.conf Alert Config (Server-side)

**Email alerts:**
```xml
<global>
  <email_notification>yes</email_notification>
  <email_to>soc@yourcompany.com</email_to>
  <smtp_server>localhost</smtp_server>
</global>

<email_alerts>
  <email_to>admin@yourcompany.com</email_to>
  <level>12</level>
  <do_not_delay>yes</do_not_delay>
</email_alerts>
```

**Active response (block user):**
```xml
<active-response>
  <command>host-deny</command>
  <location>local</location>
  <level>12</level>
  <timeout>600</timeout>
</active-response>
```

**Integration (Slack example):**
```xml
<integration>
  <name>custom-slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

### ⑦ Test & Validate

**Test rule with wazuh-logtest:**
```bash
echo 'Sep 18 16:00:00 host sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow' | /var/ossec/bin/wazuh-logtest
```
Expected: Rule `100001` triggers, level 12

**Verify monitor fires:**
- Navigate: **Alerting → Monitors → Linux Sensitive Auth File Access via Sudo → Alert history**
- Confirm alerts appear when matching events are indexed

**Dashboard visualization:**
- **Security Events → Add filter:** `rule.id: 100001`
- Save as named search for SOC team
