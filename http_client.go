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
	"bytes"
	"log"
	"net/http"

	"golang.org/x/net/context"

	"io/ioutil"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
)

// httpSafeDumpClient talks HTTP to server which is needed for GAE.
type httpSafeDumpClient struct {
	ClientConfig *pb.ClientConfig
}

func (s *httpSafeDumpClient) SourceName() string {
	return s.ClientConfig.HttpBaseUrl
}

func (s *httpSafeDumpClient) Close() error {
	return nil
}

func (s *httpSafeDumpClient) makeRequest(ctx context.Context, name string, in, out proto.Message) error {
	bin, err := proto.Marshal(in)
	if err != nil {
		return err
	}
	resp, err := http.Post(s.ClientConfig.HttpBaseUrl+"/simpleRPC/"+name, "application/binary", bytes.NewReader(bin))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bout, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 response code received from server: %d (%s)\n", resp.StatusCode, resp.Status)
		return ErrInternalError
	}

	return proto.Unmarshal(bout, out)
}

func (s *httpSafeDumpClient) GetPublicCert(ctx context.Context, req *pb.GetPublicCertRequest) (*pb.GetPublicCertResponse, error) {
	log.Printf("Requesting public certificate from %s...\n", s.SourceName())

	var resp pb.GetPublicCertResponse
	err := s.makeRequest(ctx, "GetPublicCert", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s *httpSafeDumpClient) DecryptSecret(ctx context.Context, req *pb.DecryptSecretRequest) (*pb.DecryptSecretResponse, error) {
	log.Printf("Requesting decryption key from %s...\n", s.SourceName())

	var resp pb.DecryptSecretResponse
	err := s.makeRequest(ctx, "DecryptSecret", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
