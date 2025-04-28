package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"time"
)

var hostname string
var climit, wlimit int

func main() {
	configureFlags()

	flag.Parse()

	checkCert(hostname)
}

func configureFlags() {
	const (
		defaultHostname = "example.com"
		defaultClimit   = 5
		defaultWlimit   = 30
	)
	flag.StringVar(&hostname, "H", "example.com", "hostname to check certificate of")
	flag.IntVar(&climit, "c", defaultClimit, "threshold for critical message")
	flag.IntVar(&wlimit, "w", defaultWlimit, "threshold for warning message")
}

func checkCert(host string) {

	now := time.Now()

	conn, err := tls.Dial("tcp", host+":443", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	if now.AddDate(0, 0, wlimit).After(cert.NotAfter) {
		exp := int(cert.NotAfter.Sub(now).Hours() / 24)
		if exp < climit {
			fmt.Printf("ALERT! Certificate expires in %d days, on %s\n", exp, cert.NotAfter.String())
		} else {
			fmt.Printf("WARNING! Certificate expires in %d days, on %s\n", exp, cert.NotAfter.String())
		}
		return
	}
	fmt.Printf("Certificate for %s is OK, will expire on %s\n", host, cert.NotAfter.String())
	return

}
