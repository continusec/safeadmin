# Problem Statement

After seeing [yet another data breach](http://www.news.com.au/technology/red-cross-blood-service-exposes-more-than-550000-medical-records-in-record-data-breach/news-story/bafc5218c7cba1238f87dab6db8b7238) due to inadvertent SQL dumps being left on the wrong server (or at least a similar cause) the author made the following observations:

Many organizations often dump data from databases using pipelines such as:

    mysqldump mydb | bzip2 -c > dump_mydb_2016-11-01.sql.bz2

And restore in similar pipelines such as:

    bzcat dump_mydb_2016-11-01.sql.bz2 | mysql mydb

The business reasons for needing to do these types of operations vary, but, with the exception of genuine backups, are often to facilitate ad-hoc operations such as restoring staging/test environment to a snapshot of production etc.

Since many of these operations are ad-hoc, often various data dumps are forgotten about, and eventually over time the environments are re-purposed and data becomes increasing likely to accidentally leak.


# Introducing `safedump` / `saferestore`

Add the following to the pipeline:

```bash
mysqldump mydb | bzip2 -c | safedump -for 24h > dump_mydb_2016-11-01.sql.bz2
```

And on the other end:

```bash
saferestore < dump_mydb_2016-11-01.sql.bz2 | bzcat | mysql mydb
```

 `safedump` encrypts the data such that it can be decrypted for the specified time period only (it defaults to 1 day).


 `saferestore` is its counterpart, that is able to decrypt the file, but only if we are inside the window specified when it was encrypted.

# Quickstart - using SafeDump Public Key Server

1. Install [golang](https://golang.org/dl/), and ensure `$GOPATH/bin` is in your `$PATH`

2. Install the `safedump` and `saferestore` binaries:

	```bash
	go get -u github.com/continusec/safeadmin/cmd/{safedump,saferestore}
	```

3. Done! Verify it works end-to-end:

	```bash
	echo Test | safedump -for 10s | saferestore
	```

## `safedump` options

Will choose server to connect to based on `~/.safedump_config` - see below.

Will cache the current certificate for a server inside of `~/.safedump_cache/`.

```
$ safedump -help
Usage of safedump:
  -chunks
    	If set, base64 and put in a chunk suitable for use in a larger file such as a log
  -for duration
    	Duration for which this data may be restored (default 24h0m0s)
```

## `saferestore` options

Will choose server to connect to based on `~/.safedump_config` - see below.


```
$ saferestore -help
Usage of saferestore:
  -chunks
    	If set, look for chunks and decode them rather than entire file
  -skip-local-check
    	If set, skip client date check and send to server anyway
```

Note: `-skip-local-check` is a "feel-good" option to help verify that the server will reject a decryption request for an object that is past TTL (without setting this, the client won't even try to contact the server in such a case).

# Protocol details

For `safedump` and `saferestore` to operate, they require connectivity to a SafeDump Key Server that supports the following two functions.

(By default, a public SafeDump Key Server is used. It is recommended to run your own Key Server, an implentation is provided)


## Get Current Certificate

Returns a short-lived self-signed certificate that includes an RSA public-key and a validity period. The validity period (a typical validity period may be from now until 7 days in the future) signifies what time period the server will accept decryption requests for objects encrypted with this key.

It additionally returns the time when the server will next generate a new certificate. Typical clients will cache the current certificate until this time.

When `safedump` runs, it checks to see if it has a currently valid certificate in `~/.safedump_cache/` for the configured server, which allows encryption up to the date specified by the invocation, and if not it contacts the configured server (per `~/.safedump_config`, defaulting to the public key server) to fetch an updated certificate.

Once a valid certificate is found, `safedump` then generates locally a once-off 256-bit AES key, and encrypts this using OAEP with the public key from the certificate using the requested TTL (now + 24 hours in our example) as the label input.

A header including the SPKI SHA256 fingerprint of the certificate that contained the public key used to encrypt the private key, the TTL and the OAEP result is written to `stdout`, followed by the rest of `stdin` encrypted using AES CTR with the generated AES key.


## Decrypt Private Key

Takes as input the header with the SPKI fingerprint, TTL and encrypted OAEP result. The server validates that the current time is before the TTL, and if so, proceeds to load the private key associated with the SPKI fingerprint, checks that the TTL is within the validity period for the associated certificate, and if so, decrypts the OAEP data (with the TTL encoded as a label). The decrypted key is returned to the client.

When `saferestore` runs, it reads from `stdin` the header as written by `safedump`, sends this header only to the server as configured in `~/.safedump_config` (defaulting to the public key server, gets the private key used to encrypt back, and then uses this to decrypt the data stream which it writes to `stdout`.


# Running your own server

Two server implementations are provided. The recommended option for private servers is to use the gRPC server.

## gRPC Server (recommended)

The gRPC server implements the SafeDump protocol. It accepts connections over the gRPC protocol, and writes certificates/keys to a specified directory.

Unlike the public key server, the gRPC server does not automatically purge old private keys. This means that administrators with direct access to this directory can choose to override the TTL specified in encrypted files by using the `breakglassrestore` tool.

### Starting the server (`servesafedump`)

1. Grab the binary:

	```bash
	go get -u github.com/continusec/safeadmin/cmd/servesafedump
	```

2. Create a server configuration file:

	```proto
	# Address (host:port) to listen for gRPC requests on (HTTP/2).
	listen_bind: ":10001"

	# tcp4 or tcp6
	listen_protocol: "tcp4"

	# TLS cert / key to use for gRPC server. The following will generate a self-signed certificate:
	# openssl req -x509 -newkey rsa:4096 -keyout grpc-key.pem -out grpc-cert.pem -days 3600 -nodes -subj '/CN=localhost' -batch
	server_cert_path: "grpc-cert.pem"
	server_key_path: "grpc-key.pem"

	# Where keys and certificates will be stored:
	archived_keys_dir: "/path/to/archived_keys_dir"

	# What is the maximum duration that a client can encrypt data for?
	# Note that due to certificate rotation periods, the actual max for a client will be between this and this + the rotation period)
	max_decryption_period: "168h"

	# How often will the server rotate the current certificate?
	certificate_rotation_period: "24h"

	# Should the server purge old keys?
	purge_old_keys: true

	# How long, after the normal key expiration, should old keys be kept for breakglass usage?
   key_retention_period: "720h" # 30 days
	```

3. Start the server:

	```bash
	servesafedump /path/to/config
	```

4. Remember to configure your clients to use this server (by populating `~/.safedump_config`).

### Out-of-band decryption (`breakglassrestore`)

Sometimes it may become necessary for an administrator to decrypt a file that the server refuses to decrypt (e.g. the TTL has passed for a file).

Use of this tool requires direct server access, specifically read access to the directory that `servesafedump` is configured to write certificates to.

To use this tool (which, unlike the client tools, ignores any client configuration):

```bash
breakglassrestore -keys /path/to/archived_keys_dir < encryptedfile
```

## Google App Engine server (used by Public Key Server)

The Google App Engine server is very similar to the gRPC server, however instead of persisting data to a filesystem directory, it writes to Google Cloud Datastore. It is configured to purge old keys, and to do so with no retention period, meaning it is not possible to provide `breakglassrestore` access to data encrypted using this server.

The following assumes the [SDK for Google App Engine (Go)](https://cloud.google.com/appengine/docs/standard/go/download) has already been downloaded and installed.

To run the local Google App Engine development server:

```bash
goapp serve cmd/gaesafedumpserver
```

To deploy the GAE app:

```bash
goapp deploy cmd/gaesafedumpserver
```

# Client Configuration

(Skip this section unless you are running your own server)

The client tools will search for configuration in the following order:

1. If `~/.safedump_config` exists, then this file is used.
2. If `/etc/safedump_config` exists, then this file is used.
3. Fall back to default configuration, which is to use the SafeDump Public Key Server.

The configuration file format is a text protobuf format, and should contain the following content:

## gRPC protocol

For gRPC protocol (recommended for private servers):

```proto
protocol: GRPC_PROTOCOL

# host:port of grpc server
grpc_server: "safedump.example.com:10001"

# One of the following 3 options should be used:

# Option 1: If your gRPC certificate is signed by a CA trusted by the clients operating system, set this:
use_system_ca_for_grpc: true

# Option 2: If using a self-signed gRPC certificate, then include the full PEM encoded certificate for the gRPC server here
grpc_cert: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"

# Option 3: Disable host validation. Should only be used by lazy debuggers.
no_grpc_security: true
```

## HTTP(S) protocol

For HTTP(S) protocol (as currently used by the SafeDump Public Key Server) you need the following configuration:

```proto
protocol: HTTP_PROTOCOL

# includes protocol, no trailing slash
http_base_url: "https://safedump-public-key-server.appspot.com"
```

Note that if no configuration file is found, the above values are used by default.


## Side-note: Why two transport protocols?

gRPC is the preferred transport protocol, however support for gRPC within Google App Engine (which currently hosts the SafeDump Public Key Server) does not appear stable yet. Hence we include a simpler HTTP(S) protocol, even though we consider it born deprecated.


## Developer Notes

To rebuild the protobuf files:

```bash
rm -rf pb
mkdir pb
protoc --go_out=plugins=grpc:pb safedump.proto
```

To rebuild all non-GAE binaries and compile the GAE code:

```bash
go install github.com/continusec/safeadmin/cmd/{safedump,saferestore,servesafedump,breakglassrestore,gaesafedumpserver}
```

# FAQ

## How does `safedump` and `saferestore` authenticate to the server?

They don't. The aim of this tool is to be simple to roll out, and an improvement on the status quo (unencrypted files on disk). It is not intended to be the only security mechanism for protecting dump files.

## How can I decrypt a file after the expiry time?

When using the Public Key Server, this is not possible. If you are running your own private key server, and have direct access to the server, use the `breakglassrestore` tool (provided that the keys are not yet been purged).


## Is all my data being sent into the cloud?

No. Even when using the public key server, the only data sent to the public key server is the encrypted header, which the SPKI hash of the certificate used to encrypt the file, the expiration date for the encryption on the file, and the encrypted key that was generated for this file (total a couple of KB). The server decryptes the encrypted key and returns it, allowing the `saferestore` tool to decrypt the remainder of the file.

## Should I run my own private key server?

Yes. In most instances you will want to do so, as it provides lower latency, and means that an someone with receipt of an encrypted file will also need access to your private key server in order to decrypt it. It also allows your administrators the ability to recover encrypted files that are past their TTL, but prior to key purging, which, by design, the public key server will not do.

The public key server is primarily intended for demonstrative purposes and we make no guarantees or warranties about any aspect of its operation.

## What files can I clean up?

`safedump` will write cached public certificates to the `~/.safedump_cache/` directory. If you only over connect to one server, then there should be only one small file in there. This directory can be safely deleted at any time, however is retained for convenience, because if a valid certificate is found there, running `safedump` can be achieved without needing to contact the server at all.

# Contact information

If you find these tools useful, please drop us a note telling us that you're using it.

Feedback and pull-requests welcome!

Adam Eijdenberg <adam@continusec.com>
