/*

Copyright 2017 Continusec Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/continusec/safeadmin"
)

func main() {
	var duration time.Duration
	var chunks bool

	flag.DurationVar(&duration, "for", 24*time.Hour, "Duration for which this data may be restored")
	flag.BoolVar(&chunks, "chunks", false, "If set, base64 and put in a chunk suitable for use in a larger file such as a log")
	flag.Parse()

	client, err := safeadmin.CreateClientFromConfiguration()
	if err != nil {
		log.Fatalf("Error loading configuration: %s\n", err)
	}
	defer client.Close()

	ttl := time.Now().Add(duration)

	log.Println("Encrypting until:", ttl)

	err = client.EncryptWithTTL(ttl, os.Stdin, os.Stdout, chunks)
	switch err {
	case nil:
	// great!
	case safeadmin.ErrInvalidDate:
		log.Fatalf("The server you are connecting to does not allow decryption that far into the future. Try a smaller period, or consider running your own private key server.")
	default:
		log.Fatalf("Error encrypting: %s\n", err)
	}
}
