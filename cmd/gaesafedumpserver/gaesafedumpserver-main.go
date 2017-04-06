package gaesafedumpserver

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"io/ioutil"

	"github.com/continusec/safeadmin"
	"github.com/continusec/safeadmin/pb"
	"github.com/golang/protobuf/proto"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
)

func init() {
	server := &safeadmin.SafeDumpServer{
		Storage:                   &GoogleCloudDatastorePersistenceLayer{},
		MaxDecryptionPeriod:       time.Hour * 24 * 7,
		CertificateRotationPeriod: time.Hour * 24,
		PurgeOldKeys:              true,
		KeyRetentionPeriod:        time.Duration(0), // don't store for any additional time
	}

	http.HandleFunc("/simpleRPC/GetPublicCert", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		req := &pb.GetPublicCertRequest{}
		if commonStart(ctx, w, r, req) {
			resp, err := server.GetPublicCert(ctx, req)
			commonEnd(ctx, w, resp, err)
		}
	})
	http.HandleFunc("/simpleRPC/DecryptSecret", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		req := &pb.DecryptSecretRequest{}
		if commonStart(ctx, w, r, req) {
			resp, err := server.DecryptSecret(ctx, req)
			commonEnd(ctx, w, resp, err)
		}
	})
	http.HandleFunc("/tasks/CronPurge", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		err := server.CronPurge(ctx)
		if err != nil {
			log.Errorf(ctx, "Error running cron: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

// commonStart reads the POST data, and unmarshals into the given message
// Returns True if ready to go. If error occurs, error message is sent
// and returns False
func commonStart(ctx context.Context, w http.ResponseWriter, r *http.Request, req proto.Message) bool {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	defer r.Body.Close()
	input, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf(ctx, "Error reading request: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	err = proto.Unmarshal(input, req)
	if err != nil {
		log.Errorf(ctx, "Error unmarshaling: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	return true
}

// commonEnd marshals the proto, and writes it out, if the given error is clean
func commonEnd(ctx context.Context, w http.ResponseWriter, resp proto.Message, err error) {
	switch err {
	case nil:
	// all good
	case safeadmin.ErrInvalidDate:
		// Send different response on this, since it's a "normal" error
		w.WriteHeader(http.StatusBadRequest)
		return
	default:
		log.Errorf(ctx, "Error decrypting: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	output, err := proto.Marshal(resp)
	if err != nil {
		log.Errorf(ctx, "Error marshaling: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(output) // ignore error, too late anyway
}
