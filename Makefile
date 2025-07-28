# use GNU standard variable names: https://www.gnu.org/prep/standards/html_node/Directory-Variables.html
DESTDIR :=
prefix := /usr/local
exec_prefix := $(prefix)
bindir := $(exec_prefix)/bin

.PHONY: all
all: target

target: cmd/*/*.go pb/*.go *.go
	env GOBIN=$(PWD)/target go install ./cmd/...
	touch target


.PHONY: run-sample-server
run-sample-server: target examples/archived-keys examples/grpc-key.pem examples/grpc-cert.pem
	@echo "About to run sample server. To use it, set SSL_CERT_FILE=./examples/grpc-cert.pem. For example:"
	@echo "SSL_CERT_FILE=./examples/grpc-cert.pem ./target/safedump < README.md > readme.encrypted"
	@echo "SSL_CERT_FILE=./examples/grpc-cert.pem ./target/saferestore < readme.encrypted"
	./target/servesafedump ./examples/server-config.proto

examples/archived-keys:
	mkdir -p examples/archived-keys

examples/grpc-key.pem examples/grpc-cert.pem:
	openssl req -x509 -sha256 -newkey rsa:4096 -keyout ./examples/grpc-key.pem -out ./examples/grpc-cert.pem -days 3600 -nodes -subj '/CN=localhost' -addext "subjectAltName = DNS:localhost"  -batch

# copy them to /usr/local/bin - normally run with sudo
.PHONY: install
install: all
	cp -t "$(DESTDIR)${bindir}" target/*

.PHONY: clean
clean:
	git clean -xfd

.PHONY: test

test:
	go test ./...

pb: safedump.proto
	mkdir -p pb
	protoc --go_out=pb --go_opt=paths=source_relative --go-grpc_out=pb --go-grpc_opt=paths=source_relative -I. safedump.proto
	touch pb