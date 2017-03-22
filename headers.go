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
	"errors"

	"github.com/continusec/safeadmin/pb"
)

var (
	// ErrBadCert means we are unable to parse the certificate
	ErrBadCert = errors.New("Unable to understand baked-in cert")

	// ErrCertNotValidBefore means certificate is not valid yet
	ErrCertNotValidBefore = errors.New("Cert is not valid before now")

	// ErrCertNotValidAfter means certificate has expired
	ErrCertNotValidAfter = errors.New("Cert is not after before now")

	// ErrCertNotRSA means certificate is not using RSA algorithm
	ErrCertNotRSA = errors.New("Cert should be RSA algorithm")

	// ErrCertWontCast means certifcate won't cast to the type we expect
	ErrCertWontCast = errors.New("Cert public key won't cast")

	// ErrUnexpectedLengthOfBlock means we have the wrong block length
	ErrUnexpectedLengthOfBlock = errors.New("Unexpected length of block")

	// ErrTTLExpired means the TTL has expired for a key
	ErrTTLExpired = errors.New("TTL expired")

	// ErrUnableToLoadKey means we are unable to parse a key
	ErrUnableToLoadKey = errors.New("Unable to parse key")

	// ErrUnableToDecrypt means we are unable to decrypt the data
	ErrUnableToDecrypt = errors.New("Unable to decrypt")
)

// Oracle defines an object that is capable of extracted the private key material
// from an encrypted header. Typically this involves an RPC to a server.
type Oracle interface {
	GetPrivateKey(*pb.EncryptedHeader) ([]byte, error)
}
