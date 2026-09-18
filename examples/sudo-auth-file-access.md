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
- **Schedule:** Every 1 minute

### ③ Extraction Query (Query DSL Editor)

Select **Extraction query editor** and paste:

```json
{
  "size": 1000,
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "from": "{{period_end}}||-1m",
              "to": "{{period_end}}",
              "include_lower": true,
              "include_upper": true,
              "boost": 1
            }
          }
        },
        {
          "range": {
            "rule.id": {
              "from": 100001,
              "to": 100001,
              "include_lower": true,
              "include_upper": true,
              "boost": 1
            }
          }
        },
        {
          "term": {
            "process.name": "sudo"
          }
        },
        {
          "regexp": {
            "dissect.content": {
              "value": "COMMAND=.*(/etc/shadow|/etc/passwd|/etc/gshadow)",
              "flags": "ALL",
              "case_insensitive": false,
              "max_determinized_states": 10000,
              "boost": 1
            }
          }
        }
      ],
      "adjust_pure_negative": true,
      "boost": 1
    }
  },
  "track_total_hits": 2147483647,
  "aggregations": {
    "by_user": {
      "terms": {
        "field": "data.user.name",
        "missing": "unknown",
        "size": 20,
        "min_doc_count": 1,
        "shard_min_doc_count": 0,
        "show_term_doc_count_error": false,
        "order": [
          { "_count": "desc" },
          { "_key": "asc" }
        ]
      },
      "aggregations": {
        "sample_alerts": {
          "top_hits": {
            "from": 0,
            "size": 5,
            "version": false,
            "seq_no_primary_term": false,
            "explain": false,
            "_source": {
              "includes": [
                "@timestamp",
                "agent.name",
                "data.user.name",
                "data.process.name",
                "data.dissect.content",
                "rule.id",
                "rule.level",
                "rule.description"
              ],
              "excludes": []
            },
            "sort": [
              {
                "@timestamp": {
                  "order": "desc"
                }
              }
            ]
          }
        }
      }
    }
  }
}
```

**Parameter breakdown:**
| Parameter | Value | Purpose |
|---|---|---|
| `size` | 1000 | Max raw hits returned |
| `filter[0].range.@timestamp` | `{{period_end}}||-1m` to `{{period_end}}` | 1-minute lookback window |
| `filter[1].range.rule.id` | `from: 100001, to: 100001` | Scope to this rule only |
| `filter[2].term.process.name` | `sudo` | Match process field |
| `filter[3].regexp.dissect.content` | `COMMAND=.*shadow...` | OR match via regex |
| `track_total_hits` | 2147483647 | Accurate total count |
| `aggregations.by_user` | `data.user.name` | Group alerts by user |
| `top_hits._source.includes` | 8 fields | Return only relevant fields |
| `top_hits.sort` | `@timestamp desc` | Latest alerts first |

### ④ Trigger Condition
- **Condition type:** Per bucket (aggregation monitor)
- **Threshold expression:**
```
ctx.results[0].aggregations.by_user.buckets.size() > 0
```

### ⑤ Action Configuration

**Email action template:**
```
Subject: [Wazuh] Sensitive Auth File Access via Sudo - Rule 100001

Body:
Monitor {{ctx.monitor.name}} triggered at {{ctx.periodEnd}}.

{{#ctx.results[0].aggregations.by_user.buckets}}
User: {{key}} ({{doc_count}} hits)
{{#sample_alerts.hits.hits}}
  - Agent: {{_source.agent.name}} | Time: {{_source.@timestamp}} | Command: {{_source.data.dissect.content}}
{{/sample_alerts.hits.hits}}
{{/ctx.results[0].aggregations.by_user.buckets}}

MITRE: T1003 - Credential Access
```

**Webhook action template:**
```json
{
  "monitor": "{{ctx.monitor.name}}",
  "trigger": "{{ctx.trigger.name}}",
  "rule_id": "100001",
  "time": "{{ctx.periodEnd}}",
  "buckets": "{{ctx.results[0].aggregations.by_user.buckets}}"
}
```

### ⑥ ossec.conf Alert Config

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

**Active response:**
```xml
<active-response>
  <command>host-deny</command>
  <location>local</location>
  <level>12</level>
  <timeout>600</timeout>
</active-response>
```

**Integration (Slack):**
```xml
<integration>
  <name>custom-slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

### ⑦ Test & Validate

**Test rule:**
```bash
echo 'Sep 18 16:00:00 host sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow' | /var/ossec/bin/wazuh-logtest
```

**Verify monitor:**
- **Alerting → Monitors → Monitor details → Alert history**

**Dashboard filter:**
- Security Events → filter: `rule.id: 100001` → Save as search
