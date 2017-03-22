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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io/ioutil"
	"log"
	"path/filepath"
	"time"

	context "golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
	homedir "github.com/mitchellh/go-homedir"
)

// LoadClientConfiguration loads the client configuration file from the
// standard location, "~/.safedump_config"
func LoadClientConfiguration() (*pb.ClientConfig, error) {
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

	return conf, nil
}

// GetPublicKeyIfValidForNow parses an X509 DER certificate, and then if considered valid
// for the specified time, returns the RSA public key, and the sha256 has of the SPKI.
func GetPublicKeyIfValidForNow(der []byte, now time.Time) (*rsa.PublicKey, []byte, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if now.Before(certificate.NotBefore) {
		return nil, nil, ErrCertNotValidBefore
	}
	if now.After(certificate.NotAfter) {
		return nil, nil, ErrCertNotValidAfter
	}
	if certificate.PublicKeyAlgorithm != x509.RSA {
		return nil, nil, ErrCertNotRSA
	}
	rsaPubKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, ErrCertWontCast
	}

	spki := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return rsaPubKey, spki[:], nil
}

// GetCurrentCertificate checks to see if there is a valid cached certificate in "~/.safedump_cached_cert_for_<server hash>"
// and if not, fetches one and write it out.
func GetCurrentCertificate(config *pb.ClientConfig, now time.Time) (*rsa.PublicKey, []byte, error) {
	hd, err := homedir.Dir()
	if err != nil {
		return nil, nil, err
	}
	// Make sure the cached cert is unique per server, or we'll encode with a key that won't decode
	hb := sha256.Sum256([]byte(config.GrpcServer))
	path := filepath.Join(hd, ".safedump_cached_cert_for_"+hex.EncodeToString(hb[:]))
	cd, err := ioutil.ReadFile(path)
	if err == nil {
		rv, spki, err := GetPublicKeyIfValidForNow(cd, now)
		if err == nil {
			return rv, spki, nil
		} // else, we'll fetch a new one
	} // else, we'll fetch a new one

	conn, err := createGrpcConn(config)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	client := pb.NewSafeDumpServiceClient(conn)

	resp, err := client.GetPublicCert(context.Background(), &pb.GetPublicCertRequest{})
	if err != nil {
		return nil, nil, err
	}

	rv, spki, err := GetPublicKeyIfValidForNow(resp.Der, now)
	if err != nil {
		return nil, nil, err
	}

	err = ioutil.WriteFile(path, resp.Der, 0644)
	if err != nil {
		return nil, nil, err
	}

	return rv, spki, nil
}

func createGrpcConn(config *pb.ClientConfig) (*grpc.ClientConn, error) {
	// Get certs
	var dialOptions []grpc.DialOption
	if config.NoGrpcSecurity {
		// use system CA pool but disable cert validation
		log.Println("WARNING: Disabling TLS authentication when connecting to gRPC server")
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	} else if config.UseSystemCaForGrpc {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))) // uses the system CA pool
	} else {
		// use baked in cert
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM([]byte(config.GrpcCert)) {
			return nil, ErrBadCert
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: cp})))
	}

	conn, err := grpc.Dial(config.GrpcServer, dialOptions...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
