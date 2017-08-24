package selfsign_test

import (
	"crypto/tls"
	"net/http"

	"github.com/davars/selfsign"
)

func ExampleGetCertificate() {
	s := &http.Server{
		Addr:      ":https",
		TLSConfig: &tls.Config{GetCertificate: selfsign.GetCertificate},
	}
	s.ListenAndServeTLS("", "")
}
