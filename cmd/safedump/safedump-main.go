/*

Copyright 2016 Continusec Pty Ltd

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
	"os"
	"time"

	"github.com/continusec/safeadmin"
)

func main() {
	var days int

	flag.IntVar(&days, "days", 1, "How many days the data should be decryptable for without manual intervention")

	config, err := safeadmin.LoadClientConfiguration()
	if err != nil {
		panic(err)
	}

	now := time.Now()

	rsaPubKey, spki, err := safeadmin.GetCurrentCertificate(config, now)
	if err != nil {
		panic(err)
	}

	err = safeadmin.EncryptWithTTL(rsaPubKey, spki, now.Add(days*24*time.Hour), os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}
