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
	"encoding/hex"
	"io/ioutil"
	"path"
	"sync"
	"time"

	pb "github.com/continusec/safeadmin/proto"
)

// KeyDirOracle is an oracle that can produce a key by loading directly
// from the specified KeyDir. This is usually used by server and breakglass
// components.
type KeyDirOracle struct {
	// KeyDir is a path to the directory that contains the private keys
	KeyDir string

	// IgnoreTTL if set means that the oracle should disregard the TTL in EncryptedHeaders.
	// The server should never set this, however it is useful for breakglass applications.
	IgnoreTTL bool

	// Lock for access to the map
	keyLock *sync.Mutex

	// Map of lowercase hex SPKI sha256 hash to private key material
	keys map[string]*rsa.PrivateKey
}

// Init must be called before any other operations. This initializes data structures to
// empty values
func (kdo *KeyDirOracle) Init() error {
	kdo.keyLock = &sync.Mutex{}
	kdo.keys = make(map[string]*rsa.PrivateKey)
	return nil
}

// PersistKey stores both the public certficate (in X509 DER format) and the private key
// material (PKCS1 DER format) in the KeyDir for this oracle. Key is kept cached in the oracle.
func (kdo *KeyDirOracle) PersistKey(certDer []byte, pkey *rsa.PrivateKey) error {
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return err
	}

	hb := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiName := hex.EncodeToString(hb[:])

	err = ioutil.WriteFile(path.Join(kdo.KeyDir, spkiName+".cert.der"), certDer, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path.Join(kdo.KeyDir, spkiName+".key.der"), x509.MarshalPKCS1PrivateKey(pkey), 0600)
	if err != nil {
		return err
	}

	kdo.keyLock.Lock()
	defer kdo.keyLock.Unlock()

	kdo.keys[spkiName] = pkey

	return nil
}

// LoadRSAPrivateKey locates and loads the private key for the specified SPKI sha256 hash
func (kdo *KeyDirOracle) LoadRSAPrivateKey(spki []byte) (*rsa.PrivateKey, error) {
	kdo.keyLock.Lock()
	defer kdo.keyLock.Unlock()

	spkiName := hex.EncodeToString(spki)
	rv, ok := kdo.keys[spkiName]
	if ok {
		return rv, nil
	}

	der, err := ioutil.ReadFile(path.Join(kdo.KeyDir, spkiName+".key.der"))
	if err != nil {
		return nil, err
	}

	pkey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, ErrUnableToLoadKey // Obscure the actual error
	}

	kdo.keys[spkiName] = pkey
	return pkey, nil
}

// GetPrivateKey takes an EncryptedHeader and if the oracle allows it (that is, the TTL is not expired,
// and the private key is located), then the decrypted material (usually a private key) is returned.
func (kdo *KeyDirOracle) GetPrivateKey(eh *pb.EncryptedHeader) ([]byte, error) {
	if !kdo.IgnoreTTL {
		if time.Now().After(time.Unix(eh.Ttl, 0)) {
			return nil, ErrTTLExpired
		}
	}

	rsaKey, err := kdo.LoadRSAPrivateKey(eh.SpkiFingerprint)
	if err != nil {
		return nil, err
	}

	ttlb := make([]byte, 8)
	binary.BigEndian.PutUint64(ttlb, uint64(eh.Ttl))

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, eh.EncryptedKey, ttlb)
	if err != nil {
		return nil, ErrUnableToDecrypt
	}

	return key, nil
}
