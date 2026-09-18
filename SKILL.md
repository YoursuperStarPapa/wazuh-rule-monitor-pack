---
name: "wazuh-rule-monitor"
description: "Create Wazuh 4.14.5 XML rules and dashboard monitor config from user-provided rule name and logic."
---

# Wazuh Rule & Monitor Creator

Target: Wazuh 4.14.5

## Workflow

1. Collect inputs from user:
   - **Rule name** — descriptive name for the rule
   - **Detection logic** — what conditions/events the rule should match (log source, field patterns, thresholds, groupings)
   - **Rule ID** (optional) — if user has a preferred ID; otherwise suggest from 100000-129999 local range
   - **Level** (optional) — severity 0-16; otherwise suggest based on described threat

2. Generate XML rule in Wazuh 4.14.5 format:
   - Use `<if_sid>0</if_sid>` for independent rules (no parent-child unless user specifies)
   - All field matching: `<field name="" type="pcre2">` with PCRE2 regex
   - Negate conditions: `<field name="" type="pcre2" negate="yes">`
   - Keep rules minimal — no unnecessary `<group>` wrappers or extra tags
   - MITRE: simple `<mitre><id>T1003</id></mitre>` (no sub-IDs unless user specifies)
   - Write to a file at `wazuh-rules/<rule_name>.xml` in workspace

3. Generate monitor configuration guide with FULL detail:

   **① Verify rule loaded**
   - Dashboard: **Wazuh Dashboard → Management → Rules** → search by ID or name

   **② Create Monitor**
   - Navigate: **Wazuh Dashboard → OpenSearch Plugins → Alerting → Monitors → Create monitor**
   - Monitor name: match rule name
   - Index: `wazuh-alerts-*`
   - Schedule: define frequency (e.g. every 1 minute)

   **③ Extraction Query (full OpenSearch monitor format)**
   - Method: **Extraction query editor** (not visual editor)
   - Always provide complete JSON with these required parameters:
     - `size`: result size (default 1000)
     - `query.bool.filter`: array containing:
       - `range.@timestamp`: `{{period_end}}||-1m` to `{{period_end}}` (time window)
       - `range.rule.id`: from/to with the rule ID
       - Any additional field filters from the XML rule logic
     - `track_total_hits`: 2147483647
     - `aggregations`: group-by aggregation (e.g. `data.srcip`, `agent.name`, `data.user.name`) with nested `top_hits` for sample alerts
   - Map XML rule fields to filter clauses:
     - `<field name="X" type="pcre2">pattern` → `{"term":{"X":"value"}}` or `{"regexp":{"X":"pattern"}}`
     - `<field name="X" negate="yes">` → move to `must_not` or exclude from filter
   - The `rule.id` range filter always uses `from: <id>, to: <id>` to scope to this rule

   **④ Trigger Condition**
   - For aggregation monitors: `ctx.results[0].aggregations.<agg_name>.buckets.size() > 0`
   - For simple monitors: `ctx.results[0].hits.total.value > 0`

   **⑤ Action Configuration**
   - Email: subject + body template with `{{ctx}}` variables
   - Webhook: JSON payload template
   - Include: `{{ctx.monitor.name}}`, `{{ctx.trigger.name}}`, `{{ctx.results[0].aggregations}}`

   **⑥ ossec.conf Alert Config**
   - Email alerts: `<email_alerts>` + `<global>` config
   - Active response: `<active-response>` block if applicable
   - Integration: `<integration>` block (Slack, PagerDuty, etc.)

   **⑦ Test & Validate**
   - Test with `wazuh-logtest`
   - Verify monitor fires: **Alerting → Monitors → Monitor details → Alert history**

4. Validate:
   - Confirm XML is well-formed
   - Verify rule ID in valid local range (100000-129999) or user-specified

## Output Format

### Section 1: XML Rule
```xml
<rule id="<id>" level="<level>">
  <if_sid>0</if_sid>
  <field name="process.name" type="pcre2">^sudo$</field>
  <description>Rule description here</description>
  <mitre><id>T1003</id></mitre>
</rule>
```

### Section 2: Monitor & Alert Config
Must include ALL subsections ①–⑦. The extraction query (③) must be a complete, copy-pasteable JSON block with all parameters: `size`, `query.bool.filter` (timestamp range + rule.id range + field filters), `track_total_hits`, and `aggregations` with `top_hits`.

## Extraction Query Template

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
              "from": <RULE_ID>,
              "to": <RULE_ID>,
              "include_lower": true,
              "include_upper": true,
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
    "by_<field>": {
      "terms": {
        "field": "<groupby_field>",
        "missing": "unknown",
        "size": 20,
        "min_doc_count": 1,
        "shard_min_doc_count": 0,
        "show_term_doc_count_error": false,
        "order": [{ "_count": "desc" }, { "_key": "asc" }]
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
              "includes": ["<fields_to_return>"],
              "excludes": []
            },
            "sort": [{ "@timestamp": { "order": "desc" } }]
          }
        }
      }
    }
  }
}
```

## `_source.includes` Field Selection

Always include baseline fields, then add rule-specific fields.

**Baseline fields (always include):**
```
@timestamp, agent.name, rule.id, rule.level, rule.description, rule.groups
```

**Rule-specific fields:** map from XML `<field name="X">` to index field path:
| XML field name | Index field |
|---|---|
| process.name | `data.process.name` |
| user.name | `data.user.name` |
| data.srcip | `data.srcip` |
| data.dstip | `data.dstip` |
| data.srcport | `data.srcport` |
| data.dstport | `data.dstport` |
| dissect.content | `data.dissect.content` |
| data.command | `data.command` |
| process.ppid | `data.process.ppid` |
| data.systemname | `data.systemname` |
| full_log | `full_log` |

**Common Wazuh alert index fields:**
```
@timestamp                    — event time
agent.name                    — agent hostname
agent.id                      — agent ID
rule.id                       — rule ID
rule.level                    — severity level
rule.description              — rule description
rule.groups                   — rule groups array
rule.mitre.id                 — MITRE technique IDs
data.srcip                    — source IP
data.dstip                    — destination IP
data.srcport                  — source port
data.dstport                  — destination port
data.user.name                — username
data.process.name             — process name
data.process.ppid             — parent PID
data.dissect.content          — dissected log content
data.command                  — command executed
data.systemname               — system name
manager.name                  — Wazuh manager name
decoder.name                  — decoder used
location                      — log source location
full_log                      — raw original log
```

**Field discovery methods:**
1. **Dashboard → Management → Indexer Management → Indices → wazuh-alerts-* → Mappings**
2. **Dashboard → Explore → Discover → expand a document → see all _source fields**
3. **API:** `curl -s "https://WAZUH_MANAGER:9200/wazuh-alerts-*/_mapping" | python3 -m json.tool`

**Quick start:** use `"includes": ["@timestamp", "agent.name", "rule.*", "data.*"]` then narrow down.

## Notes

- Always use Wazuh 4.14.5 syntax (v4 rule format)
- Default to local_rules.xml conventions (rule ID 100000+)
- Extraction query uses `{{period_end}}` template variable for time window
- Aggregation field should match the logical grouping (e.g., source IP, user, agent)
- Ask for clarification if logic is vague
