package burrow_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/happydave/burrow"
)

// A configuration file, a tunnel kept up by a Redialer, and an HTTP client
// whose connections run through the tunnel's userspace network stack.
func ExampleLoadConfig() {
	cfg, ignored, err := burrow.LoadConfig("client.ovpn")
	if err != nil {
		log.Fatal(err)
	}
	for _, ig := range ignored {
		log.Printf("ignored %s (line %d): no meaning without a device", ig.Directive, ig.Line)
	}
	// Attempts from several processes on one host share a file store, so the
	// admission guard counts all of them. It lives in this user's own cache
	// directory, where no other user can create its files first.
	dir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}
	cfg.AdmissionStore = burrow.NewFileStore(filepath.Join(dir, "burrow-attempts.json"))

	r := burrow.NewRedialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tn, err := r.Next(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer tn.Close()

	client := &http.Client{Transport: &http.Transport{DialContext: tn.DialContext}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.88.0.1:8080/hello.txt", nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s", body)
}
