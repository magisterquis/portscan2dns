Portscan 2 DNS
==============

Portscan2DNS is a simple portscanner which reports the ports it finds open via
DNS.

Targets can be specified as CIDR ranges, IP addresses, or hostnames.  Please
run with `-h` for a complete list of options.

For legal use only.

Example
-------
Scanner:
```bash
portscan2dns -domain example.com -ports 22,23,80,443,8000-8010 192.168.1.1 192.168.1.35 192.168.1.36 192.168.1.37
```

Catcher:
```bash
tcpdump -lnni vio0 udp port 53 | perl -ne '$_=lc;s/.*\? ([^.]+).*/\1/;next if$a{$_};$a{$_}=1;s/-/./g;s/p/:/;print'
```
