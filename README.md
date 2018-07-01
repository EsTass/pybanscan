# pybanscan
python log scanner for bad actions and ip bans

# Description

Check results from cmd actions and search for malicious activity based in regexp, banning IPs based on params on `config.ini` file.
Each `title` in `config.ini` have his own options to detect or exclude activity.

Bans are based on cmd and can be configured by params:
- `-cmdban "iptables -I INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -I INPUT -p udp -s %IP% --dport %PORT% -j DROP"`
- `-cmdunban "iptables -D INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -D INPUT -p udp -s %IP% --dport %PORT% -j DROP"`
- `-cmdcheckban "iptables -C INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -C INPUT -p udp -s %IP% --dport %PORT% -j DROP"`
By default its configured for `iptables` IP:port tcp and udp

# Usage

```
USAGE
pybanscan.py [options]

OPTIONS

 -h : help
 -v : verbose mode
 -vd : verbose debug mode
 -flog "./pybanscan.pkl" : log file with pickle warning data
 -t 5 : time to wait for check in minutes
 -c : check only one time and exit
 -ct "title" : check only title and exit
 -fc "./config.ini" : file config ini format
 -fccreate "./config.ini" : create example config file
 -fctest "./config.ini" : check config file
 -pd : show actual warnings data
 #With port (Default)
 -cmdban "iptables -I INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -I INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for ban action
 -cmdunban "iptables -D INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -D INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for unban action
 -cmdcheckban "iptables -C INPUT -p tcp -s %IP% --dport %PORT% -j DROP && iptables -C INPUT -p udp -s %IP% --dport %PORT% -j DROP" : cmd for check exist action
 #Without port
 -cmdban "iptables -I INPUT -s %IP% -j DROP" : cmd for ban action NO PORT
 -cmdunban "iptables -D INPUT -s %IP% -j DROP" : cmd for unban action NO PORT
 -cmdcheckban "iptables -C INPUT -s %IP% -j DROP" : cmd for check exist action NO PORT
 #Excluded IPs
 -ipexclude "0.0.0.0,127.0.0.1,192.168.1.1"
 -ipexcludef "./excips.txt"

CONFIG. Ini file format with each title

[title]
active=False
logcmd=cat /var/log/file
logcmd_line_split=\\n|empty
grepdatetime=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{4})
grepdateformat=%Y-%m-%dT%H:%M:%S%z
grepip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
grepactions=(Invalid\ user|Failed\ Password|Bad\ protocol|attack)
grepactionsignore=session\ open|session\ clos|pam_unix|pam_systemd|Accepted)
bantime=24
banchecks=3
bancheckstime=60
banport=22
```

# Install

Download files, rename `config.example` to `config.ini`, edit and change needed and run with sudo

# Example

Run with defaults, verbose mode, reading `config.ini` file, with excluded IPs in file `./excip.txt` and checking every 1 minute
```
sudo ./pybanscan.py -v -t 1 -ipexcludef './excip.txt'
```
