# Example: Linux Sensitive Authentication File Access via Sudo

## User Input
- **Rule name:** Linux Sensitive Authentication File Access via Sudo
- **Logic:** process.name:sudo and dissect.content:*COMMAND=* and dissect.content:(*/etc/shadow* or */etc/passwd* or */etc/gshadow*)

## Generated XML Rule

```xml
<!-- Rule: Linux Sensitive Authentication File Access via Sudo -->
<!-- Wazuh 4.14.5 | Place in /var/ossec/etc/rules/local_rules.xml or include file -->

<group name="linux,sudo,authentication,pci_dss_10.2.5,pci_dss_10.2.7">

  <!-- Parent rule: sudo command executed -->
  <rule id="100001" level="0">
    <if_sid>5502</if_sid>
    <description>Sudo command executed - base rule for sudo activity monitoring</description>
    <group>sudo_command,</group>
  </rule>

  <!-- Child rule: sudo accessing sensitive authentication files -->
  <rule id="100002" level="12">
    <if_sid>100001</if_sid>
    <match>COMMAND=</match>
    <regex>(/etc/shadow|/etc/passwd|/etc/gshadow)</regex>
    <description>Linux sensitive authentication file accessed via sudo - possible credential harvesting</description>
    <mitre>
      <id>T1003.008</id>
      <id>T1552.001</id>
    </mitre>
    <group>authentication_file_access,credential_access,pci_dss_10.2.5,pci_dss_10.2.7,</group>
    <info type="link">https://attack.mitre.org/techniques/T1003/008/</info>
  </rule>

</group>
```

## Generated Monitor Config

### ① Deploy
```bash
sudo cp linux-sensitive-auth-file-access-via-sudo.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

### ② Verify in Dashboard
- Wazuh Dashboard → Management → Rules → search `100002`

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
- Security Events → Add filter: `rule.id: 100002` → Save as search
