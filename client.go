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
	"io"
	"log"
	"time"

	"golang.org/x/net/context"

	"crypto/x509"

	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
)

// SafeDumpClient is used to interact with a given server
type SafeDumpClient struct {
	// Server is the server that we talk to
	Server SafeDumpServiceClient

	// Storage is used to cache public certs
	Storage SafeDumpPersistence

	// SendKnownBadDateToServer allows us to request decryption of files that we know have the wrong TTL. Useful for breakglass utilities.
	SendKnownBadDateToServer bool
}

// Close should be called to close all underlying connections
func (c *SafeDumpClient) Close() error {
	return c.Server.Close()
}

// EncryptWithTTL will generate a symmetric key, then encrypt this using the specified public key and TTL,
// write this out, and then apply a stream cipher to in, copying to out. The number of bytes written to out
// will be the same as those written to in with a small constant number of bytes added to it.
// If chunk is set, then output is suitable for embedded in a larger file (e.g. log file)
func (c *SafeDumpClient) EncryptWithTTL(ttl time.Time, in io.Reader, out io.Writer, chunk bool) error {
	sn := c.Server.SourceName()
	if len(sn) == 0 {
		log.Println("Attempting to encrypt, but missing config about which server to connect to. Failing.")
		return ErrInvalidConfig
	}

	ctx := context.Background()
	hb := sha256.Sum256([]byte(sn))

	// Try to load from disk
	bb, err := c.Storage.Load(ctx, hb[:])
	switch err {
	case nil:
		var pcr pb.GetPublicCertResponse
		err = proto.Unmarshal(bb, &pcr)
		if err != nil {
			return err
		}
		rsaKey, spki, err := parseSpkiAndValidate(pcr.Der, ttl)
		switch err {
		case nil:
			return streamEncryptWithKey(rsaKey, spki, ttl, in, out, chunk)
		case ErrInvalidDate:
			if time.Now().Before(time.Unix(pcr.Ttl, 0)) {
				return err
			}
			// else, continue
		default:
			return err
		}
	case ErrStorageKeyNotFound:
		// continue
	default:
		return err
	}

	// Default behavior, if we couldn't make do with the cert we had, is fetch one
	pcr, err := c.fetchNewPublicCertRes(ctx)
	if err != nil {
		return err
	}
	rsaKey, spki, err := parseSpkiAndValidate(pcr.Der, ttl)
	if err != nil {
		return err
	}
	return streamEncryptWithKey(rsaKey, spki, ttl, in, out, chunk)
}

// DecryptWithTTL reads an encrypted header, then decrypts the stream, copying to out. Note that since we don't MAC,
// we make no guarantees about integrity or authentication.
// If chunks is set, then look for chunks to decode as part of a larger file, instead of the whole stream.
// For now, if chunks is set, then the entire input stream is read before processing commences.
func (c *SafeDumpClient) DecryptWithTTL(in io.Reader, out io.Writer, chunks bool) error {
	return streamDecryptWithHeader(context.Background(), c.Server, in, out, chunks, c.SendKnownBadDateToServer)
}

func (c *SafeDumpClient) fetchNewPublicCertRes(ctx context.Context) (*pb.GetPublicCertResponse, error) {
	rv, err := c.Server.GetPublicCert(ctx, &pb.GetPublicCertRequest{})
	if err != nil {
		return nil, err
	}

	rawBytes, err := proto.Marshal(rv)
	if err != nil {
		return nil, err
	}

	hb := sha256.Sum256([]byte(c.Server.SourceName()))

	err = c.Storage.Save(ctx, hb[:], rawBytes, time.Unix(rv.Ttl, 0))
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func parseSpkiAndValidate(der []byte, ttl time.Time) (*rsa.PublicKey, []byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if ttl.Before(cert.NotBefore) {
		return nil, nil, ErrInvalidDate
	}
	if ttl.After(cert.NotAfter) {
		return nil, nil, ErrInvalidDate
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		log.Println("Unexpected certificate algorithm format")
		return nil, nil, ErrInternalError
	}
	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Println("Unable to cast certificate key to RSA Public Key")
		return nil, nil, ErrInternalError
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return rsaPubKey, spki[:], nil
}
