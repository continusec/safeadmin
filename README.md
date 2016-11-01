# Problem Statement

After seeing [yet another data breach](http://www.news.com.au/technology/red-cross-blood-service-exposes-more-than-550000-medical-records-in-record-data-breach/news-story/bafc5218c7cba1238f87dab6db8b7238) due to inadvertent SQL dumps being left on the wrong server (or at least a similar cause) the author made the following observations:

Many organizations often dump data from databases using pipelines such as:

    mysqldump mydb | bzip2 -c > dump_mydb_2016-11-01.sql.bz2
    
And restore in similar pipelines such as:

    bzcat dump_mydb_2016-11-01.sql.bz2 | mysql mydb
    
The business reasons for needing to do these types of operations vary, but, with the exception of genuine backups, are often to facilitate ad-hoc operations such as restoring staging/test environment to a snapshot of production etc.

Since many of these operations are ad-hoc, often various data dumps are forgotten about, and eventually over time the environments are re-purposed.


# Introducing `safedump` / `saferestore`

Add the following to the pipeline:

    mysqldump mydb | bzip2 -c | safedump --days=2 > dump_mydb_2016-11-01.sql.bz2

And on the other end:

    saferestore < dump_mydb_2016-11-01.sql.bz2 | bzcat | mysql mydb
     
 `safedump` encrypts the data such that it can be easily decrypted for the specified time period (it defaults to 1 day), however decryption beyond this period requires manual intervention by a server administrator.
 
 `saferestore` is its counterpart, that decrypts the file (if we are inside the window specified when it was encrypted), and requires manual intervention by a server administrator outside of this period.
 
# Details

Your administrator runs a server on your network (`servesafedump` below) that performs two functions:

## Get Current Certificate

Returns a short-lived self-signed certificate that includes an RSA public-key and a validity period. This period (typically 24 hours) signifies when a client should discard this certificate from any caches to fetch a new one (if a client uses an out of date public key, they risk the server deleting the private key before the client needs it).

When `safedump --days=2` runs, it checks to see if it has a currently valid certificate in `~/.safedump_cached_cert`, and if not it contacts the configured server (per `~/.safedump_config`) to get the current certificate.

It then generates locally a once-off 256-bit AES key, and encrypts this using OAEP with the public key from the current certificate using the TTL (now + 2 days in our example) as the label input.

A header including the SPKI SHA256 fingerprint of the certificate that contained the public key used to encrypt the private key, the TTL and the OAEP result is written to `stdout`, followed by the rest of `stdin` encrypted using AES CTR with the generated AES key.


## Decrypt Private Key

Takes as input the header with the SPKI fingerprint, TTL and encrypted OAEP result. The server validates that the current time is before the TTL, and if so, proceeds to load the private key associated with the SPKI fingerprint, and decrypts the OAEP data (with the TTL encoded as a label). The decrypted key is returned to the client.

`saferestore` reads from `stdin` the header as written by `safedump`, sends this to the server as configured in `~/.safedump_config`, gets the private key used to encrypt back, and then uses this to decrypt the data stream which it writes to `stdout`.

## Running a server

Install [golang](https://golang.org/dl/), then:

    go get github.com/continusec/safeadmin/cmd/servesafedump

Create a directory where certs and keys will be written to. You may wish to delete old keys so that data cannot be recovered.

    mkdir /var/certs
    
Generate a TLS certificate for your server, e.g.

    openssl req -x509 -newkey rsa:4096 -keyout grpc-key.pem -out grpc-cert.pem -days 3600 -nodes -subj '/CN=localhost' -batch
    
Create a configuration file for your server, e.g.
	
    cat <<EOF > server_config.proto
    # Port to listen for gRPC requests on (HTTP/2).
    listen_port: 10001

    # TLS cert / key to use for gRPC server, e.g.
    server_cert_path: "grpc-cert.pem"
    server_key_path: "grpc-key.pem"

    # New certificates and keys will be dropped into this directory before use
    archived_keys_dir: "/var/certs"
    EOF

Run the server:

    servesafedump server_config.proto	

## Installing `safedump` and `saferestore`

Install [golang](https://golang.org/dl/), then:

    go get github.com/continusec/safeadmin/cmd/safedump
    go get github.com/continusec/safeadmin/cmd/saferestore

Create a configuration file for your client, e.g.
	
    cat <<EOF > ~/.safedump_config
    # Host:port for the server
    grpc_server: "localhost:10001"

    # Cert for the server
    grpc_cert: "-----BEGIN CERTIFICATE-----\nMII...iCXwqM06Cg==\n-----END CERTIFICATE-----\n"
    EOF

Alternatively, if you have a real certificate (not self-signed), replace `grpc_cert: ...` with:

    use_system_ca_for_grpc: true

Now, happily pipe to/from `safedump` and `saferestore`.


# FAQ

## How does `safedump` and `saferestore` authenticate to the server?

They don't. The aim of this tool is to be simple to roll-out, and an improvment on the status quo (unencrypted files on disk). It is not intended to be the only security mechanism for protecting dump files.

## How can I decrypt a file after the expiry time?

The server saves all of the private keys to the certs directory specified in the server config. It would be a good exercise to write a tool that can be run out-of-band to do this - but I haven't needed to yet.

# Contact information
Adam Eijdenberg <adam@continusec.com>

