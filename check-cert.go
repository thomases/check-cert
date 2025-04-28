package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"time"
)

var hostname string

func main() {
	configureFlags()

	flag.Parse()

	checkCert(hostname)
}

func configureFlags() {
	const (
		defaultHostname = "example.com"
	)
	flag.StringVar(&hostname, "H", "example.com", "hostname to check certificate of")
}

func checkCert(host string) {

	now := time.Now()

	conn, err := tls.Dial("tcp", host+":443", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	if now.AddDate(0, 0, 30).After(cert.NotAfter) {
		exp := int64(cert.NotAfter.Sub(now).Hours() / 24)
		if exp < 5 {
			fmt.Printf("ALERT! Certificate expires in %d on %s\n", exp, cert.NotAfter.String())
		} else {
			fmt.Printf("WARNING! Certificate expires in %d on %s\n", exp, cert.NotAfter.String())
		}
		return
	}
	fmt.Printf("Certificate for %s is OK, will expire on %s\n", host, cert.NotAfter.String())
	return

}
