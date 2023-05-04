package main

/*
 * portscan2dns_test.go
 * Tests for portscan2dns.go
 * By J. Stuart McMurray
 * Created 20230503
 * Last Modified 20230503
 */

import "testing"

func TestReportLabel(t *testing.T) {
	salt = "kittens"
	for _, c := range []struct {
		host string
		port string
		want string
	}{{
		host: "0.0.0.0",
		port: "0",
		want: "894e7f785ec39ee4e407b96c986a5cff430b4b220e2ef216e69ac7ee",
	}, {
		host: "f:f",
		port: "123",
		want: "d5a93ce0ff43d1a04b6fa0d3f8b6e48e76e93a5732f8c3ccdc5def6a",
	}, {
		host: "127.0.0.1",
		port: "8888",
		want: "52d047c3f537dc50dbe8207ebf52403382284960f43373ab24a05176",
	}} {
		c := c /* :( */
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got, err := reportLabel(hostport{
				host: c.host,
				port: c.port,
			})
			if nil != err {
				t.Errorf("err: %q", err)
				return
			}
			if got != c.want {
				t.Errorf("got: %q", got)
			}
		})
	}
}
