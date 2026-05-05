# Recommended Actions: Detailed Command Set and Explanation

## Purpose

This document expands the remediation and detection improvement section for Scenario 01: SSH Invalid User Authentication Attempts.

The goal is to document not only what should be done, but also how each action can be performed and verified.

> Important: Some hardening actions can lock you out of the server if performed in the wrong order. Always test a new trusted access method before disabling password login, root login, or broad SSH firewall access.

## Execution Locations

| Action Area | Where to Run |
|---|---|
| Check public administrator IP | MacBook Air |
| Review `/var/log/auth.log` | Ubuntu Target |
| Review login history | Ubuntu Target |
| Configure UFW firewall | Ubuntu Target |
| Create non-root admin user | Ubuntu Target |
| Generate SSH key | MacBook Air |
| Copy SSH public key | MacBook Air and Ubuntu Target |
| Harden SSH configuration | Ubuntu Target |
| Install Fail2ban | Ubuntu Target |
| Add Wazuh custom rule | Wazuh Server |
| Review alerts | Wazuh Dashboard / Browser |

## Action 1 - Verify Whether the Same Source IP Had Any Successful SSH Login

### Purpose

Confirm whether the activity was limited to failed authentication attempts or whether the source IP successfully logged in later.

### Command

Run on Ubuntu Target:

```bash
grep "<SOURCE_IP>" /var/log/auth.log | grep -E "Accepted|Failed|Invalid|Connection closed"
```

### Explanation

| Part | Meaning |
|---|---|
| `grep "<SOURCE_IP>" /var/log/auth.log` | Searches the Linux authentication log for all events related to the source IP. |
| `grep -E "Accepted|Failed|Invalid|Connection closed"` | Filters the output to show important SSH authentication outcomes. |
| `Accepted` | Indicates a successful SSH login. |
| `Failed` | Indicates a failed login attempt. |
| `Invalid` | Indicates that the username does not exist on the system. |
| `Connection closed` | Indicates the SSH session was closed before successful authentication. |

### Additional Command

```bash
grep "Accepted" /var/log/auth.log | tail -n 30
```

### Explanation

| Part | Meaning |
|---|---|
| `grep "Accepted" /var/log/auth.log` | Finds successful SSH authentication records. |
| `tail -n 30` | Shows only the latest 30 matching lines. |

### Additional Command

```bash
last -i | head -n 20
```

### Explanation

| Part | Meaning |
|---|---|
| `last` | Displays recent login sessions. |
| `-i` | Shows source IP addresses. |
| `head -n 20` | Displays the latest 20 login records. |

### Expected Investigation Result

```text
No successful SSH login from the same source IP was observed.
```

## Action 2 - Restrict SSH Access to Trusted Source IP Addresses

### Purpose

Reduce SSH exposure by allowing access only from trusted administrator IP addresses.

### Step 1: Check the Current Public IP from the Administrator Machine

Run on MacBook Air:

```bash
curl -4 ifconfig.me
```

### Explanation

| Part | Meaning |
|---|---|
| `curl` | Sends an HTTP request from the current machine. |
| `-4` | Forces IPv4 output. |
| `ifconfig.me` | Returns the public IP address seen by the internet. |

### Step 2: Check Current Firewall Rules on the Ubuntu Target

Run on Ubuntu Target:

```bash
ufw status numbered
```

### Explanation

| Part | Meaning |
|---|---|
| `ufw` | Uncomplicated Firewall, a Linux firewall management tool. |
| `status numbered` | Lists firewall rules with rule numbers, which are needed when deleting rules. |

### Step 3: Allow SSH Only from a Trusted IP

Run on Ubuntu Target:

```bash
ufw allow from <trusted_admin_ip> to any port 22 proto tcp
```

Example:

```bash
ufw allow from <TRUSTED_ADMIN_IP> to any port 22 proto tcp
```

### Explanation

| Part | Meaning |
|---|---|
| `ufw allow` | Adds an allow rule. |
| `from <trusted_admin_ip>` | Only permits traffic from this source IP. |
| `to any port 22` | Applies the rule to local SSH port 22. |
| `proto tcp` | Applies the rule to TCP traffic only. |

### Step 4: Remove Broad SSH Access

Check the rules again:

```bash
ufw status numbered
```

If there is a rule like:

```text
22/tcp ALLOW IN Anywhere
```

Delete it by rule number:

```bash
ufw delete <rule_number>
```

### Important Note

Do not close the current SSH session until a new SSH connection from the trusted IP has been tested successfully.

## Action 3 - Create a Non-Root Administrative User for SSH Access

### Purpose

Avoid using direct root SSH login for daily administration.

### Command

Run on Ubuntu Target:

```bash
adduser analyst
```

### Explanation

| Part | Meaning |
|---|---|
| `adduser` | Creates a new Linux user interactively. |
| `analyst` | The new username for administrative access. |

### Command

```bash
usermod -aG sudo analyst
```

### Explanation

| Part | Meaning |
|---|---|
| `usermod` | Modifies an existing user account. |
| `-aG` | Appends the user to a supplementary group. |
| `sudo` | The administrative group on Ubuntu. |
| `analyst` | The user being added to the sudo group. |

### Validation Command

```bash
id analyst
```

### Explanation

This confirms that the user exists and belongs to the correct groups.

## Action 4 - Configure SSH Key-Based Authentication

### Purpose

Replace password-based SSH access with public key authentication.

### Step 1: Generate an SSH Key on the Administrator Machine

Run on MacBook Air:

```bash
ssh-keygen -t ed25519 -C "soc-lab-target"
```

### Explanation

| Part | Meaning |
|---|---|
| `ssh-keygen` | Generates a new SSH key pair. |
| `-t ed25519` | Uses the Ed25519 key algorithm. |
| `-C "soc-lab-target"` | Adds a comment to identify the key. |

### Step 2: Copy the Public Key to the Ubuntu Target

Run on MacBook Air:

```bash
ssh-copy-id analyst@<TARGET_PUBLIC_IP>
```

### Explanation

| Part | Meaning |
|---|---|
| `ssh-copy-id` | Copies the local public key to the remote user's `authorized_keys` file. |
| `analyst@<TARGET_PUBLIC_IP>` | Logs in as the `analyst` user on the Ubuntu target. |

### Alternative Command if `ssh-copy-id` Is Not Available

Run on MacBook Air:

```bash
cat ~/.ssh/id_ed25519.pub | ssh root@<TARGET_PUBLIC_IP> "mkdir -p /home/analyst/.ssh && cat >> /home/analyst/.ssh/authorized_keys && chown -R analyst:analyst /home/analyst/.ssh && chmod 700 /home/analyst/.ssh && chmod 600 /home/analyst/.ssh/authorized_keys"
```

### Explanation

| Part | Meaning |
|---|---|
| `cat ~/.ssh/id_ed25519.pub` | Reads the local public key. |
| `ssh root@<TARGET_PUBLIC_IP>` | Connects to the target as root. |
| `mkdir -p /home/analyst/.ssh` | Creates the `.ssh` directory if it does not exist. |
| `cat >> authorized_keys` | Appends the public key to the authorized keys file. |
| `chown -R analyst:analyst` | Gives ownership of the `.ssh` directory to the `analyst` user. |
| `chmod 700 /home/analyst/.ssh` | Restricts directory permissions. |
| `chmod 600 authorized_keys` | Restricts key file permissions. |

### Step 3: Test SSH Key Login

Run on MacBook Air:

```bash
ssh analyst@<TARGET_PUBLIC_IP>
```

### Expected Result

The user should be able to log in without using the root account.

## Action 5 - Disable Password-Based SSH Authentication

### Purpose

Prevent password guessing attacks from succeeding.

### Command

Run on Ubuntu Target:

```bash
nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Add:

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers analyst
```

### Explanation

| Setting | Meaning |
|---|---|
| `PasswordAuthentication no` | Disables password-based SSH login. |
| `PubkeyAuthentication yes` | Allows SSH key-based login. |
| `PermitRootLogin no` | Prevents direct root SSH login. |
| `AllowUsers analyst` | Allows only the `analyst` user to log in via SSH. |

### Validate SSH Configuration

```bash
sshd -t
```

### Explanation

| Part | Meaning |
|---|---|
| `sshd` | The OpenSSH server daemon. |
| `-t` | Tests the SSH server configuration syntax. |

If there is no output, the syntax is usually valid.

### Reload SSH Service

```bash
systemctl reload ssh
```

### Explanation

| Part | Meaning |
|---|---|
| `systemctl` | Controls system services. |
| `reload ssh` | Reloads SSH configuration without fully restarting the service. |

### Validation Command from a New Terminal

Run on MacBook Air:

```bash
ssh analyst@<TARGET_PUBLIC_IP>
```

Do not close the existing root session until this test succeeds.

## Action 6 - Deploy Fail2ban for Repeated SSH Authentication Failures

### Purpose

Automatically block source IP addresses that repeatedly fail SSH authentication.

### Install Fail2ban

Run on Ubuntu Target:

```bash
apt update
apt install -y fail2ban
```

### Explanation

| Part | Meaning |
|---|---|
| `apt update` | Refreshes the package index. |
| `apt install -y fail2ban` | Installs Fail2ban without interactive confirmation. |

### Create SSH Jail Configuration

```bash
nano /etc/fail2ban/jail.d/sshd.local
```

Add:

```text
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 10m
bantime = 1h
```

### Explanation

| Setting | Meaning |
|---|---|
| `[sshd]` | Defines the SSH protection jail. |
| `enabled = true` | Enables the SSH jail. |
| `port = ssh` | Applies protection to the SSH service. |
| `filter = sshd` | Uses the built-in SSHD filter. |
| `logpath = /var/log/auth.log` | Reads SSH authentication events from `auth.log`. |
| `maxretry = 5` | Bans an IP after 5 failed attempts. |
| `findtime = 10m` | Counts failures within a 10-minute window. |
| `bantime = 1h` | Bans the IP for 1 hour. |

### Enable and Start Fail2ban

```bash
systemctl enable --now fail2ban
```

### Check Status

```bash
systemctl status fail2ban --no-pager
```

### Check SSH Jail Status

```bash
fail2ban-client status sshd
```

### Explanation

| Command | Meaning |
|---|---|
| `systemctl enable --now fail2ban` | Enables Fail2ban at boot and starts it immediately. |
| `systemctl status fail2ban --no-pager` | Shows Fail2ban service status without paging. |
| `fail2ban-client status sshd` | Shows the SSH jail status and banned IPs. |

## Action 7 - Block a Confirmed Malicious Source IP with UFW

### Purpose

Block a confirmed malicious source IP at the host firewall level.

### Command

Run on Ubuntu Target:

```bash
ufw deny from <malicious_ip> to any port 22 proto tcp
```

Example:

```bash
ufw deny from <SOURCE_IP> to any port 22 proto tcp
```

### Explanation

| Part | Meaning |
|---|---|
| `ufw deny` | Adds a blocking rule. |
| `from <malicious_ip>` | Blocks traffic from the specified IP. |
| `to any port 22` | Applies the block to SSH. |
| `proto tcp` | Applies the rule to TCP traffic. |

### Verify Rule

```bash
ufw status numbered
```

### Remove the Block Later if Needed

```bash
ufw delete <rule_number>
```

### Important Note

Do not block the current administrator IP unless another trusted access path is available.

## Action 8 - Review SSH Security Configuration

### Purpose

Confirm that SSH hardening settings are applied correctly.

### Command

Run on Ubuntu Target:

```bash
grep -Ei "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
```

### Explanation

| Part | Meaning |
|---|---|
| `grep -Ei` | Searches text using extended regular expressions, case-insensitively. |
| `PermitRootLogin` | Shows whether root SSH login is allowed. |
| `PasswordAuthentication` | Shows whether password login is allowed. |
| `PubkeyAuthentication` | Shows whether key-based login is allowed. |
| `AllowUsers` | Shows which users are allowed to log in via SSH. |

### Expected Secure Configuration

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers analyst
```

## Action 9 - Improve Wazuh Detection for Repeated Invalid SSH Users

### Purpose

Escalate repeated invalid-user SSH attempts from the same source IP.

### Edit Local Rules on Wazuh Server

Run on Wazuh Server:

```bash
nano /var/ossec/etc/rules/local_rules.xml
```

Add:

```xml
<group name="local,sshd,authentication_failed,">
  <rule id="100100" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH invalid user login attempts from the same source IP</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
  </rule>
</group>
```

### Explanation

| Field | Meaning |
|---|---|
| `id="100100"` | Custom local Wazuh rule ID. |
| `level="10"` | Sets a higher severity level. |
| `frequency="5"` | Triggers when the condition occurs 5 times. |
| `timeframe="120"` | Uses a 120-second time window. |
| `<if_matched_sid>5710</if_matched_sid>` | Builds on Wazuh rule 5710. |
| `<same_source_ip />` | Correlates events from the same source IP. |
| `<description>` | Describes the custom alert. |
| `<mitre>` | Maps the custom rule to MITRE ATT&CK techniques. |

### Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

### Check Service Status

```bash
systemctl is-active wazuh-manager
```

### Expected Output

```text
active
```

## Action 10 - Standardize Investigation Timestamps

### Purpose

Avoid confusion between raw Linux log time and dashboard local time.

### Check System Time on Ubuntu Target

```bash
timedatectl
```

### Explanation

| Part | Meaning |
|---|---|
| `timedatectl` | Shows system time, timezone, and NTP synchronization status. |

### Check UTC Time

```bash
date -u +"%Y-%m-%dT%H:%M:%SZ"
```

### Explanation

| Part | Meaning |
|---|---|
| `date -u` | Displays UTC time. |
| `+%Y-%m-%dT%H:%M:%SZ` | Formats the time in ISO 8601 style. |

### Recommended Report Statement

```text
All technical timestamps in this report are based on raw Linux authentication logs. Dashboard timestamps may be displayed in the browser's local timezone.
```

## Summary of Defensive Improvements

| Area | Improvement |
|---|---|
| Authentication review | Check whether the suspicious IP achieved successful login. |
| SSH exposure | Restrict SSH to trusted IPs or VPN ranges. |
| Account security | Use a non-root administrative user. |
| Authentication method | Use SSH key-based authentication and disable passwords. |
| Root login | Disable direct root SSH access. |
| Automated protection | Use Fail2ban for repeated failures. |
| Firewall response | Block confirmed malicious source IPs. |
| Detection engineering | Add a Wazuh correlation rule for repeated invalid SSH attempts. |
| Time handling | Standardize investigation timestamps. |
