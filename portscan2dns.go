// Program portscan2dns is a simple portscanner which reports open ports via
// DNS queries.
package main

/*
 * portscan2dns.go
 * Portscanner which reports open ports via DNS
 * By J. Stuart McMurray
 * Created 20190423
 * Last Modified 20230503
 */

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slices"
)

/* Compile-time defaults. */
var (
	domain    string                /* Reporting domain. */
	portsList = "20-23,80,443,5900" /* Ports list. */
	timeout   = "1s"                /* Connect timeout. */

	timeoutD time.Duration /* Parsed timeout. */
)

/* hostport contains a host and port for a connection attempt */
type hostport struct {
	host string
	port string
}

var (
	/* toldh sanitizes an IP address to DNS-friendly LDH */
	toldh = strings.NewReplacer(":", "-", ".", "-").Replace

	/* Number of open ports. */
	nOpen atomic.Uint64
)

func main() {
	start := time.Now()
	/* Parse timeout, if we have one. */
	if "" != timeout {
		var err error
		if timeoutD, err = time.ParseDuration(timeout); nil != err {
			log.Fatalf(
				"Error parsing timeout %q: %s",
				timeout,
				err,
			)
		}
	}

	var (
		nAtt = flag.Uint(
			"parallel",
			16,
			"Try to connect to `N` ports in parallel",
		)
	)
	flag.StringVar(
		&domain,
		"domain",
		domain,
		"Optional DNS `domain` to which to send found open ports",
	)
	flag.StringVar(
		&portsList,
		"ports",
		portsList,
		"Comma-separated `list` of port ranges",
	)
	flag.DurationVar(
		&timeoutD,
		"timeout",
		timeoutD,
		"Port connection `timeout`",
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v target [target...]

Portscans the given target(s), which may be IP addresses, hostnames, or CIDR
ranges.  Open ports will be reported via a DNS query of the form

N-N-N-NpPORT.domain

For example, if port 22 is found to be open on 10.23.42.174 and the domain for
reporting is example.com, a query would be made for

10-23-42-174p22.example.com

IPv4 addresses will have dots replaced by hyphens.  IPv6 addresses will have
colons replaced by hyphens.

If no domain is set open ports will just be logged to the standard output.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure the domain has one leading dot and no trailing dots. */
	if "" != domain {
		domain = "." + strings.Trim(domain, ".")
	}

	/* Get ports to try */
	ports, err := parsePorts()
	if nil != err {
		log.Fatalf("Unable to parse ports list: %v", err)
	}
	if 0 == len(ports) {
		log.Fatalf("No ports specified")
	}

	/* Work out the targets to attack */
	targets, cidrs, err := parseTargets(flag.Args())
	if nil != err {
		log.Fatalf("Unable to parse targets list: %v", err)
	}
	if 0 == len(targets) && 0 == len(cidrs) {
		log.Fatalf("No targets given")
	}

	/* At this point, all errors are non-fatal */
	log.SetOutput(os.Stdout)
	log.Printf(
		"Trying %v ports against %v CIDR range(s) and "+
			"%v additional address(es)",
		len(ports),
		len(cidrs),
		len(targets),
	)

	/* Start attacker goroutines */
	var (
		wg    sync.WaitGroup
		tch   = make(chan hostport)
		count uint
	)
	for i := uint(0); i < *nAtt; i++ {
		wg.Add(1)
		go attack(tch, &wg)
	}

	/* Send targets */
	for _, p := range ports {
		/* First the non-CIDR targets */
		for _, t := range targets {
			tch <- hostport{t, p}
			count++
		}
		/* Then every address in every CIDR range */
		for _, c := range cidrs {
			for ip := c.IP.Mask(c.Mask); c.Contains(ip); func(i net.IP) {
				for j := len(ip) - 1; j >= 0; j-- {
					i[j]++
					if i[j] > 0 {
						break
					}
				}
			}(ip) {
				tch <- hostport{ip.String(), p}
				count++
			}
		}
	}

	/* Wait for attackers to finish */
	close(tch)
	wg.Wait()
	log.Printf(
		"Done.  Scanned %v host:port pairs and found %d open in %v",
		count,
		nOpen.Load(),
		time.Since(start).Round(time.Millisecond),
	)
}

// parsePorts turns the ports list into a list of port numbers.
func parsePorts() ([]string, error) {
	var is []int

	/* Get each port or range */
	for _, chunk := range strings.Split(portsList, ",") {
		if "" == chunk {
			continue
		}

		/* A number is easy */
		if !strings.Contains(chunk, "-") {
			u, err := strconv.ParseUint(chunk, 0, 16)
			if nil != err {
				return nil, err
			}
			is = append(is, int(u))
			continue
		}

		/* We've a range */
		bounds := strings.SplitN(chunk, "-", 2)
		if 2 != len(bounds) {
			return nil, fmt.Errorf("invalid port range %v", chunk)
		}
		min, err := strconv.ParseUint(bounds[0], 0, 16)
		if nil != err {
			return nil, err
		}
		max, err := strconv.ParseUint(bounds[1], 0, 16)
		if nil != err {
			return nil, err
		}
		for u := min; u <= max; u++ {
			is = append(is, int(u))
		}
	}

	/* If we've got no ports, give up */
	if 0 == len(is) {
		return nil, nil
	}

	/* Sort and dedup list */
	sort.Ints(is)
	is = slices.Compact(is)

	/* Stringify */
	ps := make([]string, len(is))
	for i, ii := range is {
		ps[i] = strconv.Itoa(ii)
	}
	return ps, nil
}

// parseTargets parses the arguments to the program and returns a list of CIDR
// ranges and targets.  If a hostname is passed to the program, it will be
// resolved.  The targets are all checked against the CIDR ranges to prevent
// duplication.  CIDR ranges are not checked against each other, however.
func parseTargets(as []string) (targets []string, cidrs []*net.IPNet, err error) {
	var tips []net.IP /* Target IPs */
	for _, a := range as {
		/* CIDR ranges are easy */
		if _, r, err := net.ParseCIDR(a); nil == err {
			cidrs = append(cidrs, r)
			continue
		}

		/* Failing that, get the address(es) for the target */
		ips, err := net.LookupIP(a)
		if nil != err {
			return nil, nil, err
		}
		/* Save any new IPs */
	IPLOOP:
		for _, ip := range ips {
			/* Make sure we haven't seen this one before */
			for _, tip := range tips {
				if ip.Equal(tip) {
					continue IPLOOP
				}
			}
			tips = append(tips, ip)
		}
	}

	/* Stringify the IPs which aren't in CIDR ranges */
	/* Make sure it's not in any CIDR range */
TIPLOOP:
	for _, tip := range tips {
		for _, cidr := range cidrs {
			if cidr.Contains(tip) {
				continue TIPLOOP
			}
		}
		targets = append(targets, tip.String())
	}

	return
}

// attack reads targets from tch, tries to connect, and if successful sends
// the host and port via DNS to the domain, if it's not the empty string.
func attack(tch <-chan hostport, wg *sync.WaitGroup) {
	defer wg.Done()
	for hp := range tch {
		attackOne(hp, wg)
	}
}

// attackOne tries to connect to the given hostport until timeout elapses.  If
// successful and the domain isn't the empty string, the host and port are sent
// to the domain via DNS.
func attackOne(hp hostport, wg *sync.WaitGroup) {
	/* Attempt to connect to the target */
	t := net.JoinHostPort(hp.host, hp.port)
	c, err := net.DialTimeout("tcp", t, timeoutD)
	if nil != err {
		log.Printf("[%v] FAIL: %v", t, err)
		return
	}
	/* If we've got it, log it and maybe send a DNS message */
	c.Close()
	nOpen.Add(1)
	log.Printf("[%v] SUCCESS", t)
	if "" != domain {
		var b strings.Builder
		b.WriteString(toldh(hp.host))
		b.WriteRune('p')
		b.WriteString(hp.port)
		b.WriteString(domain)
		wg.Add(1)
		go func() {
			defer wg.Done()
			net.LookupHost(b.String())
		}()
	}
}
