package gaesafedumpserver

import (
	"encoding/hex"
	"time"

	"google.golang.org/appengine/datastore"

	context "golang.org/x/net/context"

	"github.com/continusec/safeadmin"
	"github.com/qedus/nds"
)

type safedumpObject struct {
	Key   []byte
	Value []byte
	TTL   int64 // unix time in seconds
}

const (
	dsKind = "safedumpObject"
)

// GoogleCloudDatastorePersistenceLayer persists objects in Google Cloud Datastore,
// with a memcache cache (using qedux/nds)
type GoogleCloudDatastorePersistenceLayer struct{}

// Load returns value if found, nil otherwise
func (g *GoogleCloudDatastorePersistenceLayer) Load(ctx context.Context, key []byte) ([]byte, error) {
	var rv safedumpObject
	err := nds.Get(ctx, datastore.NewKey(ctx, dsKind, hex.EncodeToString(key), 0, nil), &rv)
	switch err {
	case nil:
		return rv.Value, nil
	case datastore.ErrNoSuchEntity:
		return nil, safeadmin.ErrStorageKeyNotFound
	default:
		return nil, err
	}
}

// Save sets value
// The TTL is a suggestion - it is up to the persistence layer whether it chooses to retain longer
func (g *GoogleCloudDatastorePersistenceLayer) Save(ctx context.Context, key, value []byte, ttl time.Time) error {
	_, err := nds.Put(ctx, datastore.NewKey(ctx, dsKind, hex.EncodeToString(key), 0, nil), &safedumpObject{
		Key:   key,
		Value: value,
		TTL:   ttl.Unix(),
	})
	return err
}
