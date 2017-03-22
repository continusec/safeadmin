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
	context "golang.org/x/net/context"

	"github.com/continusec/safeadmin/pb"
)

// GRPCOracle represents a remote key oracle, that is one that we need to contact
// over gRPC in order to get private keys.
type GRPCOracle struct {
	// Config tells use which server to connect to
	Config *pb.ClientConfig
}

// GetPrivateKey contacts the remote oracle and requests the private key material
// be decrypted from our encrypted header
func (gko *GRPCOracle) GetPrivateKey(eh *pb.EncryptedHeader) ([]byte, error) {
	conn, err := createGrpcConn(gko.Config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := pb.NewSafeDumpServiceClient(conn)

	resp, err := client.DecryptSecret(context.Background(), &pb.DecryptSecretRequest{Header: eh})
	if err != nil {
		return nil, err
	}

	return resp.Key, nil
}
