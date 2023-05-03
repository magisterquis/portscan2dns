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

"Secure" Reporting
------------------
In order to not report open ports over public DNS, ports found open can be
reported as SHA224 hashes.  To do this, supply a hard-to-guess salt value
with `-salt`.  Hashes can be brute-forced to find open IP:port pairs by
supplying the same salt and target as well as the hash, with `-target-from`.


Compile-Time Config
-------------------
The following are settable at compile-time with `-ldflags -X`:

Variable         | Default             | Description
-----------------|---------------------|-
`main.domain`    | _none_              | Reporting DNS domain
`main.portsList` | `20-23,80,443,5900` | List of ports and ranges to scan
`main.randSalt`  | `randomhash`        | Pseudosalt which causes random hashes to be sent
`main.salt`      | _none_              | If set, open ports are sent via DNS as hex(sha224(salt + host:port))
`main.timeout`   | `1s`                | TCP connect timeout
