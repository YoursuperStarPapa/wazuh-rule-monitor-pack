# Example: Linux Sensitive Authentication File Access via Sudo

## User Input
- **Rule name:** Linux Sensitive Authentication File Access via Sudo
- **Logic:** process.name:sudo and dissect.content:*COMMAND=* and dissect.content:(*/etc/shadow* or */etc/passwd* or */etc/gshadow*)

## Generated XML Rule

```xml
<rule id="100001" level="12">
  <if_sid>0</if_sid>
  <field name="process.name" type="pcre2">^sudo$</field>
  <field name="dissect.content" type="pcre2">COMMAND=.*(/etc/shadow|/etc/passwd|/etc/gshadow)</field>
  <description>Sensitive Authentication File Access via Sudo</description>
  <mitre><id>T1003</id></mitre>
</rule>
```

| Field | Value |
|---|---|
| Rule ID | 100001 |
| Level | 12 (High) |
| if_sid | 0 (independent rule) |
| MITRE | T1003 (Credential Access) |
| Logic | sudo + COMMAND= + (/etc/shadow OR /etc/passwd OR /etc/gshadow) |

## Generated Monitor Config

### ① Deploy
```bash
sudo cp linux-sensitive-auth-file-access-via-sudo.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

### ② Verify in Dashboard
- Wazuh Dashboard → Management → Rules → search `100001`

### ③ Test
```bash
echo 'Sep 18 16:00:00 host sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow' | /var/ossec/bin/wazuh-logtest
```

### ④ Email Alerts
```xml
<global>
  <email_notification>yes</email_notification>
  <email_to>soc@yourcompany.com</email_to>
</global>
<email_alerts>
  <email_to>admin@yourcompany.com</email_to>
  <level>12</level>
</email_alerts>
```

### ⑤ Active Response
```xml
<active-response>
  <command>host-deny</command>
  <location>local</location>
  <level>12</level>
  <timeout>600</timeout>
</active-response>
```

### ⑥ Dashboard Visualization
- Security Events → Add filter: `rule.id: 100001` → Save as search
