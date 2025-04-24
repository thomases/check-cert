package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"
)

func main() {
	hostname := os.Args[1]
	checkCert(hostname)
}

func checkCert(host string) {

	now := time.Now()

	conn, err := tls.Dial("tcp", host+":443", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	chain := conn.ConnectionState().VerifiedChains[0]
	cert := chain[0]
	fmt.Printf("%s %s\n", cert.Subject.CommonName, cert.NotAfter)
	if now.AddDate(0, 0, 30).After(cert.NotAfter) {
		exp := int64(cert.NotAfter.Sub(now).Hours() / 24)
		if exp < 5 {
			fmt.Printf("ALERT! Certificate expires in %d\n", exp)
		} else {
			fmt.Printf("WARNING! Certificate expires in %d\n", exp)
		}
	}

}
