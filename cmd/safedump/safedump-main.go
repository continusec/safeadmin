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
	var fragment bool

	flag.DurationVar(&duration, "for", 24*time.Hour, "Duration for which this data may be restored")
	flag.BoolVar(&fragment, "chunk", false, "If set, base64 and put in a chunk suitable for use in a larger file such as a log")
	flag.Parse()

	config, err := safeadmin.LoadClientConfiguration()
	if err != nil {
		panic(err)
	}

	now := time.Now()

	rsaPubKey, spki, err := safeadmin.GetCurrentCertificate(config, now)
	if err != nil {
		panic(err)
	}

	ttl := now.Add(duration)

	log.Println("Encrypting until:", ttl)

	err = safeadmin.EncryptWithTTL(rsaPubKey, spki, ttl, os.Stdin, os.Stdout, fragment)
	if err != nil {
		panic(err)
	}
}
