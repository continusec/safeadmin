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
	"io"
	"time"

	"golang.org/x/net/context"

	"github.com/continusec/safeadmin/pb"
)

var (
	// ErrStorageKeyNotFound returned when object not found in storage
	ErrStorageKeyNotFound = errors.New("ErrStorageKeyNotFound")

	// ErrInvalidDate returned when the date is a reason why we won't decrypt
	ErrInvalidDate = errors.New("ErrInvalidDate")

	// ErrInvalidRequest returned when an invalid request is received.
	ErrInvalidRequest = errors.New("ErrInvalidRequest")

	// ErrInternalError means that an unexpected error occurred.
	ErrInternalError = errors.New("ErrInternalError")

	// ErrInvalidConfig means the configuration is not supported.
	ErrInvalidConfig = errors.New("ErrInvalidConfig")
)

// SafeDumpPersistence is an abstraction for a persistence layer
type SafeDumpPersistence interface {
	// Load returns value if found, nil otherwise
	Load(ctx context.Context, key []byte) ([]byte, error)

	// Save sets value
	// The TTL is a suggestion - it is up to the persistence layer whether it chooses to retain longer
	Save(ctx context.Context, key, value []byte, ttl time.Time) error
}

// SafeDumpServiceClient is to combine a Closer with a Server (which is bascially the same as client)
type SafeDumpServiceClient interface {
	pb.SafeDumpServiceServer
	io.Closer

	// SourceName returns the name of the serving we are connected to. Used to key cached certs.
	SourceName() string
}
