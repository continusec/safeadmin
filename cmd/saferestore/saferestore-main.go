package main

// Generate self-signed cert:
// openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 3 -out cert.pem -subj "/CN=SafeDumper" -batch
//
// All we care about in the cert is the public key and dates.

import (
	"os"

	"github.com/continusec/safeadmin"
)

func main() {
	rsaPrivateKey, err := safeadmin.LoadPrivateRSAKey("key.pem")
	if err != nil {
		panic(err)
	}

	err = safeadmin.DecryptWithTTL(&safeadmin.PrivateKeyOracle{Key: rsaPrivateKey}, os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}
