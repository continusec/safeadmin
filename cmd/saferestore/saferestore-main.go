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

	"github.com/continusec/safeadmin"
)

func main() {
	var chunks bool

	flag.BoolVar(&chunks, "chunks", false, "If set, look for chunks and decode them rather than entire file")
	flag.Parse()

	client, err := safeadmin.CreateClientFromConfiguration()
	if err != nil {
		log.Fatalf("Error loading configuration: %s\n", err)
	}
	defer client.Close()

	err = client.DecryptWithTTL(os.Stdin, os.Stdout, chunks)
	switch err {
	case nil:
	// all good
	case safeadmin.ErrInvalidDate:
		log.Fatalf("Encryption period has expired for this file. The server is unable to provide a decryption key. If using a private server, contact your administrator to request a manual override.")
	default:
		log.Fatalf("Error decrypting: %s\n", err)
	}
}
