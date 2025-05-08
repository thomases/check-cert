package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

type CertStatus int

const (
	CERT_OK      CertStatus = iota // cert is within thresholds
	CERT_WARN                      // cert will expire within number of days set by warning limit
	CERT_CRIT                      // cert will exipre within number of days set by criticla limit
	CERT_EXPIRED                   // cert is expired
	ERROR
)

var hostname string
var climit, wlimit, port int

func main() {
	configureFlags()

	flag.Parse()

	status, _ := checkCert(hostname)

	os.Exit(int(status))
}

func configureFlags() {
	const (
		defaultHostname = "example.com"
		defaultClimit   = 5
		defaultWlimit   = 30
		defaultPort     = 443
	)
	flag.StringVar(&hostname, "H", "example.com", "hostname to check certificate of")
	flag.IntVar(&climit, "c", defaultClimit, "threshold for critical message")
	flag.IntVar(&wlimit, "w", defaultWlimit, "threshold for warning message")
	flag.IntVar(&port, "p", defaultPort, "port to connect to")
}

func checkCert(host string) (CertStatus, error) {

	now := time.Now()

	conn, err := tls.Dial("tcp", host+":"+strconv.Itoa(port), nil)
	if err != nil {
		fmt.Println(err)
		return ERROR, err
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	if now.AddDate(0, 0, wlimit).After(cert.NotAfter) {
		exp := int(cert.NotAfter.Sub(now).Hours() / 24)
		if exp <= 0 {
			fmt.Println("ALERT! Certificate is expired!")
			return CERT_EXPIRED, nil
		} else if exp < climit {
			fmt.Printf("CRITICAL! Certificate expires in %d days, on %s\n", exp, cert.NotAfter.String())
			return CERT_CRIT, nil
		} else {
			fmt.Printf("WARNING! Certificate expires in %d days, on %s\n", exp, cert.NotAfter.String())
			return CERT_WARN, nil
		}
	}
	fmt.Printf("Certificate for %s is OK, will expire on %s\n", host, cert.NotAfter.String())
	return CERT_OK, nil

}
