// 수업 6-1: Go mTLS 클라이언트. Python과 같은 다섯 경우를 부른다.
//
//	cd clients/go && go run . [https://localhost:18440/orders]
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	url := "https://localhost:18440/orders"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	base, _ := filepath.Abs("../..") // lab/mtls
	rootPEM, err := os.ReadFile(filepath.Join(base, "..", "private-ca", "out", "root.crt"))
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)

	cases := []struct{ label, dir string }{
		{"정상(orders)", "ok"}, {"인증서 없음", ""}, {"다른 CA", "otherca"},
		{"만료", "expired"}, {"다른 신원(payments)", "payments"},
	}
	title := regexp.MustCompile(`<title>(.*?)</title>`)
	for _, c := range cases {
		cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
		if c.dir != "" {
			d := filepath.Join(base, "out", c.dir)
			pair, err := tls.LoadX509KeyPair(filepath.Join(d, "chain.pem"), filepath.Join(d, "client.key"))
			if err != nil {
				panic(err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := cl.Get(url)
		if err != nil {
			fmt.Printf("%-16s → error: %v\n", c.label, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := strings.TrimSpace(string(b))
		if m := title.FindStringSubmatch(body); m != nil {
			body = m[1]
		}
		fmt.Printf("%-16s → HTTP %d %s\n", c.label, resp.StatusCode, body)
	}
}
