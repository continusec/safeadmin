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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"log"
	"math/big"
	"time"

	context "golang.org/x/net/context"

	"sync"

	"encoding/hex"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
)

// SafeDumpServer is the main server object that can handle the business logic, for the defined gRPC service,
// regardless of actually protocol and persistence layer
type SafeDumpServer struct {
	// Storage is a dumb layer that can store and load stuff
	Storage SafeDumpPersistence

	// MaxDecryptionPeriod is the maximum length of time the server will commit to being able to decrypt an object encrypted with it's certicates
	MaxDecryptionPeriod time.Duration

	// CertificationRotationPeriod is how often a fresh certificate is issued
	CertificateRotationPeriod time.Duration

	// OverrideDateChecks, if set, will skip date checks on TTL. This should only be used with breakglass tools that operate on the server directly
	OverrideDateChecks bool

	// Cache
	certLock          sync.Mutex
	cachedCurrentCert *pb.GetPublicCertResponse

	// Cache
	keysLock   sync.Mutex
	cachedKeys map[string]*keyCert // string is hex encoded spki
}

var (
	keyCurrentCert = []byte("current-cert")
)

type keyCert struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// generateNewCertificate creates a new certificate, but does not persist it.
// Returns the key/cert, as well as the time when it should next be rotated.
func (s *SafeDumpServer) generateNewCertificate() (*pb.KeyAndCert, time.Time, error) {
	now := time.Now()
	ttl := now.Add(s.MaxDecryptionPeriod + s.CertificateRotationPeriod)

	// Generate a private key
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Use a barebone template
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(0),             // appears to be a required element
		NotBefore:          now.Add(-5 * time.Minute), // allow for client clock skew
		NotAfter:           ttl,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkey.PublicKey, pkey)
	if err != nil {
		return nil, time.Time{}, err
	}

	return &pb.KeyAndCert{
		Cert: &pb.GetPublicCertResponse{
			Der: der,
			Ttl: now.Add(s.CertificateRotationPeriod).Unix(),
		},
		Key: x509.MarshalPKCS1PrivateKey(pkey),
	}, ttl, nil
}

// calcSPKI returns the SPKI SHA256 hash for the X509 DER ASN.1 encoded certificate
func calcSPKI(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	hb := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hb[:], nil
}

// rotateCertificate will generate a new cert, then save. We don't care if there's race condition, worst case we just issue 2 certs which is fine.
func (s *SafeDumpServer) rotateCertificate(ctx context.Context) (*pb.GetPublicCertResponse, error) {
	keyAndCert, keyTTL, err := s.generateNewCertificate()
	if err != nil {
		return nil, err
	}

	ksBo, err := proto.Marshal(keyAndCert)
	if err != nil {
		return nil, err
	}

	bo, err := proto.Marshal(keyAndCert.Cert)
	if err != nil {
		return nil, err
	}

	spki, err := calcSPKI(keyAndCert.Cert.Der)
	if err != nil {
		return nil, err
	}

	// First, save the key / cert. No big deal if we never use it, so no need to wrap in transaction with below
	err = s.Storage.Save(ctx, spki, ksBo, keyTTL)
	if err != nil {
		return nil, err
	}

	// Then save out the current cert record
	err = s.Storage.Save(ctx, keyCurrentCert, bo, time.Unix(keyAndCert.Cert.Ttl, 0))
	if err != nil {
		return nil, err
	}

	return keyAndCert.Cert, nil
}

// GetPublicCert is part of the service definition, it returns the current public certificate, rotating if necessary
func (s *SafeDumpServer) GetPublicCert(ctx context.Context, req *pb.GetPublicCertRequest) (*pb.GetPublicCertResponse, error) {
	log.Println("Serving GetPublicCert request...")

	s.certLock.Lock()
	defer s.certLock.Unlock()

	if s.cachedCurrentCert != nil && time.Now().Before(time.Unix(s.cachedCurrentCert.Ttl, 0)) {
		return s.cachedCurrentCert, nil
	}

	bb, err := s.Storage.Load(ctx, keyCurrentCert)
	switch err {
	case nil:
		var rv pb.GetPublicCertResponse
		err = proto.Unmarshal(bb, &rv)
		if err != nil {
			log.Printf("Error unmarshaling current certificate: %s\n", err)
			return nil, ErrInternalError
		}
		if time.Now().Before(time.Unix(rv.Ttl, 0)) {
			s.cachedCurrentCert = &rv
			return &rv, nil
		}
		// else, continue below
	case ErrStorageKeyNotFound:
		// continue below
	default:
		log.Printf("Error loading cached certificate: %s\n", err)
		return nil, ErrInternalError
	}

	rv, err := s.rotateCertificate(ctx)
	if err != nil {
		log.Printf("Error rotating certificate: %s\n", err)
		return nil, ErrInternalError
	}
	s.cachedCurrentCert = rv
	return rv, nil
}

// loadKeyAndCert returns parsed DER cert, private key for spki
func (s *SafeDumpServer) loadKeyAndCert(ctx context.Context, spki []byte) (*keyCert, error) {
	stringHash := hex.EncodeToString(spki)

	s.keysLock.Lock()
	defer s.keysLock.Unlock()

	if s.cachedKeys == nil {
		s.cachedKeys = make(map[string]*keyCert)
	}

	rv, ok := s.cachedKeys[stringHash]
	if ok {
		return rv, nil
	}

	bb, err := s.Storage.Load(ctx, spki)
	if err != nil {
		return nil, err
	}

	var ks pb.KeyAndCert
	err = proto.Unmarshal(bb, &ks)
	if err != nil {
		return nil, err
	}

	pkey, err := x509.ParsePKCS1PrivateKey(ks.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(ks.Cert.Der)
	if err != nil {
		return nil, err
	}

	rv = &keyCert{
		Certificate: cert,
		Key:         pkey,
	}
	s.cachedKeys[stringHash] = rv

	return rv, nil
}

// DecryptSecret finds the associated encryption key, and if all matches, decrypts it.
// Errors returned are ErrInvalidRequest, ErrInvalidDate, ErrInternalError, nil
func (s *SafeDumpServer) DecryptSecret(ctx context.Context, req *pb.DecryptSecretRequest) (*pb.DecryptSecretResponse, error) {
	log.Println("Serving DecryptSecret request...")

	// Do we have a header?
	if req.Header == nil {
		return nil, ErrInvalidRequest
	}

	now := time.Now()
	headerTTL := time.Unix(req.Header.Ttl, 0)

	// Is the TTL in the header before now?
	if headerTTL.Before(now) {
		if s.OverrideDateChecks {
			// allow through if in break glass mode
		} else {
			return nil, ErrInvalidDate
		}
	}

	// Load the key and cert
	ks, err := s.loadKeyAndCert(ctx, req.Header.SpkiFingerprint)
	if err != nil {
		log.Printf("Error loading key and cert: %s\n", err)
		return nil, ErrInternalError
	}

	// Verify the TTL is in the range for the cert
	if headerTTL.After(ks.Certificate.NotAfter) {
		if s.OverrideDateChecks {
			// allow through if in break glass mode
		} else {
			return nil, ErrInvalidDate
		}
	}
	if headerTTL.Before(ks.Certificate.NotBefore) {
		if s.OverrideDateChecks {
			// allow through if in break glass mode
		} else {
			return nil, ErrInvalidDate
		}
	}

	// Finally, decrypt using our key
	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(req.Header.Ttl))

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ks.Key, req.Header.EncryptedKey, ttlb)
	if err != nil {
		log.Printf("Error decrypting header: %s\n", err)
		return nil, ErrInvalidRequest
	}

	return &pb.DecryptSecretResponse{Key: key}, nil
}

// Close is a no-op for the server, but is required per the interface definition
func (s *SafeDumpServer) Close() error {
	return nil
}

// SourceName is used to key cache data. Ought not be called in this context
func (s *SafeDumpServer) SourceName() string {
	return ""
}
