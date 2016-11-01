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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"sync"
	"time"

	context "golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/continusec/safeadmin/proto"
	"github.com/golang/protobuf/proto"
)

type SafeDumpServer struct {
	Config *pb.ServerConfig

	certLock      sync.Mutex
	lastValidTime time.Time
	currentCert   []byte
	keys          map[string]*rsa.PrivateKey // hex spki sha256 hash to private key

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
		SerialNumber:       big.NewInt(0), // appears to be a required element
		NotBefore:          now,
		NotAfter:           s.lastValidTime.Add(5 * time.Minute), // 24 hours should be long enough, give a little longer to allow for clock skew
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hb := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	spkiName := hex.EncodeToString(hb[:])
	dateString := now.UTC().Format(time.RFC3339)[:10]

	err = ioutil.WriteFile(path.Join(s.Config.ArchivedKeysDir, spkiName+"_"+dateString+".cert.der"), der, 0644)
	if err != nil {
		return nil, err
	}

	// No date in this name since we want to be able to easily load it
	err = ioutil.WriteFile(path.Join(s.Config.ArchivedKeysDir, spkiName+".key.der"), x509.MarshalPKCS1PrivateKey(pkey), 0600)
	if err != nil {
		return nil, err
	}

	if s.keys == nil {
		s.keys = make(map[string]*rsa.PrivateKey)
	}
	s.keys[spkiName] = pkey

	s.currentCert = der

	return der, nil
}

func (s *SafeDumpServer) getPrivateKey(spki []byte) (*rsa.PrivateKey, error) {
	s.certLock.Lock()
	defer s.certLock.Unlock()

	if s.keys == nil {
		s.keys = make(map[string]*rsa.PrivateKey)
	}

	spkiName := hex.EncodeToString(spki[:])
	rv, ok := s.keys[spkiName]
	if ok {
		return rv, nil
	}

	der, err := ioutil.ReadFile(path.Join(s.Config.ArchivedKeysDir, spkiName+".key.der"))
	if err != nil {
		return nil, err
	}

	pkey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, err
	}

	s.keys[spkiName] = pkey

	return pkey, nil
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

	if time.Now().After(time.Unix(req.Header.Ttl, 0)) {
		return nil, errors.New("TTL expired")
	}

	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(req.Header.Ttl))

	pkey, err := s.getPrivateKey(req.Header.SpkiFingerprint)
	if err != nil {
		return nil, errors.New("Can't find private key")
	}

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pkey, req.Header.EncryptedKey, ttlb)
	if err != nil {
		return nil, errors.New("No")
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

	lis, err := net.Listen("tcp", conf.ListenBind)
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(tc))
	pb.RegisterSafeDumpServiceServer(grpcServer, &SafeDumpServer{Config: conf})

	log.Println("Serving...")
	grpcServer.Serve(lis)
}
