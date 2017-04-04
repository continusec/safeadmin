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
	"io/ioutil"
	"path/filepath"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
	homedir "github.com/mitchellh/go-homedir"
)

// CreateClientFromConfiguration loads the client configuration file from the
// standard location, "~/.safedump_config".
func CreateClientFromConfiguration() (*SafeDumpClient, error) {
	hd, err := homedir.Dir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(hd, ".safedump_config")

	confData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf := &pb.ClientConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		return nil, err
	}

	var server SafeDumpServiceClient

	switch conf.Protocol {
	case pb.ServerProtocol_GRPC_PROTOCOL:
		server = &gRPCClient{ClientConfig: conf}
	case pb.ServerProtocol_HTTP_PROTOCOL:
		server = &httpSafeDumpClient{ClientConfig: conf}
	default:
		return nil, ErrInvalidConfig
	}

	return &SafeDumpClient{
		Server:  server,
		Storage: &FilesystemPersistence{Dir: filepath.Join(hd, ".safedump_cache")},
	}, nil

}
