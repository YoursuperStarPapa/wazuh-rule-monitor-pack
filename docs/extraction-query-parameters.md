# Extraction Query Parameter Reference

Detailed explanation of every parameter in the OpenSearch monitor extraction query.

---

## Top Level

| Parameter | Value | Meaning |
|---|---|---|
| `size` | `1000` | Max number of raw hit documents returned. Controls how much raw data comes back before aggregation. |

---

## `query.bool.filter` — Query Container

Uses `bool` + `filter` (not `must`) because filter context is faster — no scoring, just match/no-match.

### Filter[0]: Time Window

```json
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
}
```

| Parameter | Meaning |
|---|---|
| `range` | Query type: match values within a range |
| `@timestamp` | The field to filter on — event timestamp |
| `from` | Start of range. `{{period_end}}` = current check time (OpenSearch template variable). `\|\|-1m` = minus 1 minute |
| `to` | End of range = current check time |
| `include_lower` | `true` = include the `from` value (>=) |
| `include_upper` | `true` = include the `to` value (<=) |
| `boost` | Relevance scoring weight. Ignored in `filter` context, but OpenSearch includes it by default |

**Purpose:** Only look at alerts from the last 1 minute window.

---

### Filter[1]: Rule ID Scoping

```json
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
}
```

| Parameter | Meaning |
|---|---|
| `from: 100001, to: 100001` | Same value = exact match (rule.id = 100001) |
| `include_lower/upper` | `true` makes it >= and <= (inclusive) |

**Purpose:** Scope to only this specific rule's alerts. Using `range` instead of `term` because rule.id is sometimes mapped as integer.

---

### Filter[2]: Field Condition (exact match)

```json
{
  "term": {
    "process.name": "sudo"
  }
}
```

| Parameter | Meaning |
|---|---|
| `term` | Exact match query (no analysis, case-sensitive) |
| `process.name` | Field from the XML rule `<field name="process.name">` |
| `"sudo"` | Exact value to match |

**Purpose:** Maps directly from XML `<field name="process.name" type="pcre2">^sudo$`.

---

### Filter[3]: Regex Condition

```json
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
```

| Parameter | Meaning |
|---|---|
| `regexp` | Regex query type |
| `dissect.content` | Field to run regex against |
| `value` | The regex pattern. `(a\|b\|c)` = OR match |
| `flags` | `ALL` = enable all optional regex features (intersection, complement, etc.) |
| `case_insensitive` | `false` = case-sensitive match |
| `max_determinized_states` | Safety limit for regex complexity. Prevents catastrophic backtracking. Default 10000 |
| `boost` | Scoring weight (ignored in filter context) |

**Purpose:** Maps from XML `<field name="dissect.content" type="pcre2">COMMAND=.*(/etc/shadow|...)`.

---

## `track_total_hits`

```json
"track_total_hits": 2147483647
```

| Parameter | Meaning |
|---|---|
| `2147483647` | Max 32-bit integer. Forces OpenSearch to count ALL matching documents accurately, not just "≥10000" |

**Purpose:** Without this, OpenSearch may return `total.value: 10000, relation: "gte"` (estimate). Setting max int forces exact count. Critical for accurate trigger thresholds.

---

## `aggregations.by_user` — Group Alerts by Field

```json
"by_user": {
  "terms": {
    "field": "data.user.name",
    "missing": "unknown",
    "size": 20,
    "min_doc_count": 1,
    "shard_min_doc_count": 0,
    "show_term_doc_count_error": false,
    "order": [{ "_count": "desc" }, { "_key": "asc" }]
  }
}
```

| Parameter | Meaning |
|---|---|
| `by_user` | Aggregation name (referenced in trigger as `aggregations.by_user.buckets`) |
| `terms` | Aggregation type: group by unique field values |
| `field` | `data.user.name` — the field to group by. Choose based on what's most useful (user, srcip, agent, etc.) |
| `missing` | `"unknown"` — documents without this field go into an "unknown" bucket instead of being excluded |
| `size` | `20` — return top 20 unique values (buckets) |
| `min_doc_count` | `1` — only return buckets with at least 1 document (skip empty) |
| `shard_min_doc_count` | `0` — at shard level, don't pre-filter (accurate counts) |
| `show_term_doc_count_error` | `false` — don't show error estimates per term (cleaner output) |
| `order` | `[{ "_count": "desc" }, { "_key": "asc" }]` — sort by count descending first, then alphabetical by key |

**Purpose:** Group alerts by user so you can see "user X had 5 hits, user Y had 3 hits".

---

## `aggregations.by_user.aggregations.sample_alerts` — Nested top_hits

```json
"sample_alerts": {
  "top_hits": {
    "from": 0,
    "size": 5,
    "version": false,
    "seq_no_primary_term": false,
    "explain": false,
    "_source": {
      "includes": ["@timestamp", "agent.name", "data.user.name", "data.process.name", "data.dissect.content", "data.srcip", "rule.id", "rule.level", "rule.description"],
      "excludes": []
    },
    "sort": [{ "@timestamp": { "order": "desc" } }]
  }
}
```

| Parameter | Meaning |
|---|---|
| `sample_alerts` | Nested aggregation name |
| `top_hits` | Aggregation type: return actual documents within each bucket |
| `from` | `0` — start from first result (pagination offset) |
| `size` | `5` — return up to 5 sample documents per bucket |
| `version` | `false` — don't include document version number |
| `seq_no_primary_term` | `false` — don't include sequence number (optimization metadata) |
| `explain` | `false` — don't include scoring explanation |
| `_source.includes` | Whitelist of fields to return. Only these fields appear in the hit — keeps response small and fast |
| `_source.excludes` | Blacklist (empty here — using includes instead) |
| `sort` | `@timestamp desc` — return the 5 most recent alerts per bucket |

**Purpose:** For each user bucket, grab the 5 most recent alerts with only the fields you need for the action message.

---

## Visual Summary

```
size: 1000
├── query.bool.filter
│   ├── [0] range @timestamp  → time window (last 1m)
│   ├── [1] range rule.id     → scope to rule 100001
│   ├── [2] term process.name → must be "sudo"
│   └── [3] regexp dissect.content → COMMAND= + sensitive files
│
├── track_total_hits: 2147483647 → accurate count
│
└── aggregations.by_user (group by data.user.name)
    ├── terms: top 20 users, sorted by count desc
    └── nested sample_alerts (top_hits)
        ├── size: 5 per user
        ├── _source.includes: 9 fields only
        └── sort: most recent first
```

---

## Field Reference Flow

```
XML Rule <field name="X">
        ↓
Extraction Query _source.includes: ["X", ...]
        ↓
Action Message: {{_source.X}}
```

All three layers must be consistent. The extraction query fetches the fields, and the action message displays them.
