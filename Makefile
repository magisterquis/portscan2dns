# Makefile
# Build portscan2dns
# By J. Stuart McMurray
# Created 20230429
# Last Modified 20230503

BINNAME=portscan2dns

.PHONY: all test build clean

all: test build

test:
	go test
	go vet
	staticcheck
	
build:
	go build -trimpath -ldflags="-w -s" -o ${BINNAME}

clean:
	rm -f ${BINNAME}
