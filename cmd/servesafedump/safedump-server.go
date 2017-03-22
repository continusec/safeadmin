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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	context "golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/safeadmin"
	pb "github.com/continusec/safeadmin/proto"
	"github.com/golang/protobuf/proto"
)

type SafeDumpServer struct {
	Config    *pb.ServerConfig
	keyOracle *safeadmin.KeyDirOracle

	certLock      sync.Mutex
	lastValidTime time.Time
	currentCert   []byte
}

func (s *SafeDumpServer) Init() error {
	s.keyOracle = &safeadmin.KeyDirOracle{KeyDir: s.Config.ArchivedKeysDir}
	err := s.keyOracle.Init()
	if err != nil {
		return err
	}

	return nil
}

// Return DER bytes for a certificate that is valid, creating a new one
// and writing to disk if needed. Cert will be valid for a short-time, e.g. 24 hours.
func (s *SafeDumpServer) getCurrentCertificate() ([]byte, error) {
	s.certLock.Lock()
	defer s.certLock.Unlock()

	now := time.Now()
	if now.Before(s.lastValidTime) && len(s.currentCert) > 0 {
		return s.currentCert, nil
	}

	// Else, we need to make one

	// Generate a private key
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Use a barebone template
	s.lastValidTime = now.Add(time.Hour * 24)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(0),                        // appears to be a required element
		NotBefore:          now.Add(-5 * time.Minute),            // allow for clock skew
		NotAfter:           s.lastValidTime.Add(5 * time.Minute), // 24 hours should be long enough, give a little longer to allow for clock skew
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return nil, err
	}

	err = s.keyOracle.PersistKey(der, pkey)
	if err != nil {
		return nil, err
	}

	s.currentCert = der

	return der, nil
}

func (s *SafeDumpServer) GetPublicCert(context.Context, *pb.GetPublicCertRequest) (*pb.GetPublicCertResponse, error) {
	der, err := s.getCurrentCertificate()
	if err != nil {
		return nil, err
	}

	log.Println("Sending current certificate...")

	return &pb.GetPublicCertResponse{Der: der}, nil
}

func (s *SafeDumpServer) DecryptSecret(ctx context.Context, req *pb.DecryptSecretRequest) (*pb.DecryptSecretResponse, error) {
	if req.Header == nil {
		return nil, errors.New("No header")
	}

	key, err := s.keyOracle.GetPrivateKey(req.Header)
	if err != nil {
		log.Println("WARNING: failed to decode:", err)
		return nil, err
	}

	log.Println("Decoded key for someone...")

	return &pb.DecryptSecretResponse{Key: key}, nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Please specify a config file for the server to use.")
	}

	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatal(err)
	}

	tc, err := credentials.NewServerTLSFromFile(conf.ServerCertPath, conf.ServerKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen(conf.ListenProtocol, conf.ListenBind)
	if err != nil {
		log.Fatal(err)
	}

	sds := &SafeDumpServer{Config: conf}
	err = sds.Init()
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(tc))
	pb.RegisterSafeDumpServiceServer(grpcServer, sds)

	log.Println("Serving...")
	grpcServer.Serve(lis)
}
