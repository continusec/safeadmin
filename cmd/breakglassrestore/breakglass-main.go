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
	var keys string
	var chunks bool

	flag.StringVar(&keys, "keys", "", "Directory containing the servesafedump storage")
	flag.BoolVar(&chunks, "chunks", false, "If set, look for chunks and decode them rather than entire file")
	flag.Parse()

	if len(keys) == 0 {
		log.Fatal("You must specify the directory containing the serversafedump storage")
	}

	client := &safeadmin.SafeDumpClient{
		Server: &safeadmin.SafeDumpServer{
			Storage: &safeadmin.FilesystemPersistence{
				Dir:       keys,
				Immutable: true,
			},
			OverrideDateChecks: true,
		},
		SendKnownBadDateToServer: true,
	}
	defer client.Close() // should be a no-op

	err := client.DecryptWithTTL(os.Stdin, os.Stdout, chunks)
	if err != nil {
		log.Fatalf("Error decrypting: %s\n", err)
	}
}
