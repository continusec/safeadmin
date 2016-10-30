package main

// Generate self-signed cert:
// openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 3 -out cert.pem -subj "/CN=SafeDumper" -batch
//
// All we care about in the cert is the public key and dates.

import (
	"os"
	"time"

	"github.com/continusec/safeadmin"
)

func main() {
	now := time.Now()

	rsaPubKey, err := safeadmin.LoadRSAKeyFromCertValidForTime("cert.pem", now)
	if err != nil {
		panic(err)
	}

	err = safeadmin.EncryptWithTTL(rsaPubKey, now.Add(3*24*time.Hour), os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}
