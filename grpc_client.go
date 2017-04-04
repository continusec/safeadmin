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
	"crypto/tls"
	"crypto/x509"
	"log"
	"sync"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/safeadmin/pb"
)

// gRPCClient wraps a client, implementing the server API, which is basically identical (but lacking dial options which we don't use anyway)
type gRPCClient struct {
	ClientConfig *pb.ClientConfig

	clientLock sync.Mutex
	grpcClient pb.SafeDumpServiceClient

	connLock       sync.Mutex
	grpcConnection *grpc.ClientConn
}

func (s *gRPCClient) getClient() (pb.SafeDumpServiceClient, error) {
	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	if s.grpcClient == nil {
		conn, err := s.getConn(true, false)
		if err != nil {
			return nil, err
		}
		s.grpcClient = pb.NewSafeDumpServiceClient(conn)
	}
	return s.grpcClient, nil
}

func (s *gRPCClient) getConn(create, unset bool) (*grpc.ClientConn, error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.grpcConnection == nil {
		if create {
			var dialOptions []grpc.DialOption
			if s.ClientConfig.NoGrpcSecurity {
				// use system CA pool but disable cert validation
				log.Println("WARNING: Disabling TLS authentication when connecting to gRPC server")
				dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
			} else if s.ClientConfig.UseSystemCaForGrpc {
				dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))) // uses the system CA pool
			} else {
				// use baked in cert
				cp := x509.NewCertPool()
				if !cp.AppendCertsFromPEM([]byte(s.ClientConfig.GrpcCert)) {
					return nil, ErrInvalidConfig
				}
				dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: cp})))
			}

			rv, err := grpc.Dial(s.ClientConfig.GrpcServer, dialOptions...)
			if err != nil {
				return nil, err
			}
			s.grpcConnection = rv
		}
		return s.grpcConnection, nil
	}
	// Else, return what we have
	rv := s.grpcConnection
	if unset {
		s.grpcConnection = nil
	}
	return rv, nil
}

func (s *gRPCClient) SourceName() string {
	return "grpc://" + s.ClientConfig.GrpcServer
}

func (s *gRPCClient) Close() error {
	conn, err := s.getConn(false, true)
	if err != nil {
		return err
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (s *gRPCClient) GetPublicCert(ctx context.Context, req *pb.GetPublicCertRequest) (*pb.GetPublicCertResponse, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	log.Printf("Requesting public certificate from %s...\n", s.SourceName())

	return client.GetPublicCert(ctx, req)
}

func (s *gRPCClient) DecryptSecret(ctx context.Context, req *pb.DecryptSecretRequest) (*pb.DecryptSecretResponse, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	log.Printf("Requesting decryption key from %s...\n", s.SourceName())

	return client.DecryptSecret(ctx, req)
}
