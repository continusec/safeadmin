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

package safeadmin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"time"

	context "golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/continusec/safeadmin/proto"
	"github.com/golang/protobuf/proto"
	homedir "github.com/mitchellh/go-homedir"
)

var (
	ErrBadCert                 = errors.New("Unable to understand baked-in cert")
	ErrCertNotValidBefore      = errors.New("Cert is not valid before now")
	ErrCertNotValidAfter       = errors.New("Cert is not after before now")
	ErrCertNotRSA              = errors.New("Cert should be RSA algorithm")
	ErrCertWontCast            = errors.New("Cert public key won't cast")
	ErrUnexpectedLengthOfBlock = errors.New("Unexpected length of block")
)

func encrypt(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	// IV is not a secret, write it out
	_, err = out.Write(iv)
	if err != nil {
		return err
	}

	// And now write the rest...
	_, err = io.Copy(&cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: out,
	}, in)
	if err != nil {
		return err
	}

	return nil
}

func decrypt(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	// IV is not a secret, write it out
	_, err = out.Write(iv)
	if err != nil {
		return err
	}

	// And now write the rest...
	_, err = io.Copy(&cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: out,
	}, in)
	if err != nil {
		return err
	}

	return nil
}

type EncryptHeader struct {
	PublicKey       *rsa.PublicKey // so server can find the right private key
	TTL             time.Time      // after which time the server requires intervention to decrypt
	EncryptedAESKey []byte         // the encrypted key (OAEP)
}

func EncryptWithTTL(rsaPubKey *rsa.PublicKey, spki []byte, ttl time.Time, in io.Reader, out io.Writer) error {
	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(ttl.Unix()))

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return err
	}

	oaepResult, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, key, ttlb)
	if err != nil {
		return err
	}

	gbs, err := proto.Marshal(&pb.EncryptedHeader{
		Ttl:             ttl.Unix(),
		EncryptedKey:    oaepResult,
		SpkiFingerprint: spki,
	})
	if err != nil {
		return err
	}

	// Length prefix the gob or we struggle to read it, since the decoder seems to be greedy
	err = binary.Write(out, binary.BigEndian, uint64(len(gbs)))
	if err != nil {
		return err
	}

	_, err = out.Write(gbs)
	if err != nil {
		return err
	}

	err = encrypt(key, in, out)
	if err != nil {
		return err
	}

	return nil
}

type Oracle interface {
	GetPrivateKey(*pb.EncryptedHeader) ([]byte, error)
}

type PrivateKeyOracle struct {
	Key *rsa.PrivateKey
}

func (pko *PrivateKeyOracle) GetPrivateKey(eh *pb.EncryptedHeader) ([]byte, error) {
	if time.Now().After(time.Unix(eh.Ttl, 0)) {
		return nil, errors.New("TTL expired.")
	}

	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(eh.Ttl))

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pko.Key, eh.EncryptedKey, ttlb)
	if err != nil {
		return nil, err
	}

	return key, nil
}

type GrpcOracle struct {
	Config *pb.ClientConfig
}

func (gko *GrpcOracle) GetPrivateKey(eh *pb.EncryptedHeader) ([]byte, error) {
	conn, err := CreateGrpcConn(gko.Config)
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

func DecryptWithTTL(keyOracle Oracle, in io.Reader, out io.Writer) error {
	var ehLen uint64
	err := binary.Read(in, binary.BigEndian, &ehLen)
	if err != nil {
		return err
	}

	if ehLen > 100000 { // sanity check, should be much smaller
		return ErrUnexpectedLengthOfBlock
	}

	ehb := make([]byte, ehLen)
	_, err = in.Read(ehb)
	if err != nil {
		return err
	}

	eh := &pb.EncryptedHeader{}
	err = proto.Unmarshal(ehb, eh)
	if err != nil {
		return err
	}

	key, err := keyOracle.GetPrivateKey(eh)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	amt, err := in.Read(iv)
	if amt == len(iv) {
		err = nil // we want to ignore EOF for now
	}
	if err != nil {
		return err
	}
	_, err = io.Copy(out, &cipher.StreamReader{S: cipher.NewCTR(block, iv), R: in})
	if err != nil {
		return err
	}

	return nil
}

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

	conn, err := CreateGrpcConn(config)
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

func CreateGrpcConn(config *pb.ClientConfig) (*grpc.ClientConn, error) {
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
