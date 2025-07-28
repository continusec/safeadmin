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

package safeadmin

import (
	"path/filepath"

	"os"

	"github.com/continusec/safeadmin/pb"
	homedir "github.com/mitchellh/go-homedir"
	"google.golang.org/protobuf/encoding/prototext"
)

// CreateClientFromConfiguration loads the client configuration file from the
// standard location, "~/.safedump_config". If no file exists at that location,
// it will fall back to "/etc/safedump_config", and it that does not exist, we fall
// back to using a public key server
func CreateClientFromConfiguration() (*SafeDumpClient, error) {
	hd, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(hd, ".safedump_config")
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		path = "/etc/safedump_config"
	}

	conf := &pb.ClientConfig{}

	confData, err := os.ReadFile(path)
	switch {
	case err == nil:
		err = prototext.Unmarshal(confData, conf)
		if err != nil {
			return nil, err
		}
	case os.IsNotExist(err): // default to localhost key server
		var ok bool
		conf.GrpcServer, ok = os.LookupEnv("SAFE_ADMIN_ADDRESS")
		if !ok {
			conf.GrpcServer = "localhost:10001"
		}
	default:
		return nil, err
	}

	return &SafeDumpClient{
		Server:  &gRPCClient{ClientConfig: conf},
		Storage: &FilesystemPersistence{Dir: filepath.Join(hd, ".safedump_cache")},
	}, nil

}
