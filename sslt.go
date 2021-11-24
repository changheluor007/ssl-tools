package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

var ShellFolder, _ = os.Getwd()
var host = flag.String("hostname", "localhost", "Specified domain name")
var RootCommonName = flag.String("RootCommonName", "GTS Root R1", "Specified Root CommonName")
var MidCommonName = flag.String("MidCommonName", "GTS CA 1C3", "Specified Mid CommonName")
var rootPath = ShellFolder + "/ssl/"
var author = "XRSec"

func checkErr(err error) {
	if err != nil {
		log.Printf(err.Error())
	}
}

func genCert(template, parent *x509.Certificate, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (*x509.Certificate, *bytes.Buffer, *bytes.Buffer) {
	caBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}
	cert, err := x509.ParseCertificate(caBytes)
	checkErr(err)

	certPEM, certPrivKeyPEM := new(bytes.Buffer), new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	checkErr(err)

	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	checkErr(err)
	return cert, certPEM, certPrivKeyPEM
}

func certSetup(SerialNumber int64, commonName *string, years int, state bool,template0 *x509.Certificate,privkey0 *rsa.PrivateKey) (*rsa.PrivateKey,*x509.Certificate,*x509.Certificate, *bytes.Buffer, *bytes.Buffer) {
	privkey, err := rsa.GenerateKey(rand.Reader, 4096)
	checkErr(err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(SerialNumber),
		Subject: pkix.Name{
			CommonName: *commonName,
		},
		NotBefore:   	time.Now(),
		NotAfter:    	time.Now().AddDate(years, 0, 0),
		ExtKeyUsage: 	[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    	x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		MaxPathLen: 	int(SerialNumber),
	}
	if state == true {
		template.IsCA = state
		template.BasicConstraintsValid = state
		template.Subject.Organization = []string{"Google Trust Services LLC"}
		template.Subject.Country = []string{"US"}
	} else if net.ParseIP(*host) == nil {
		template.DNSNames = append(template.DNSNames, *host)
	} else {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(*host))
	}
	if SerialNumber == 1 {
		template.MaxPathLenZero = false
	} else if SerialNumber== 0 {
		template.MaxPathLenZero = true
	}
	if template0 == nil {
		template0 = template
		privkey0 = privkey
	}
	cert, certPEM, privKeyPEM := genCert(template, template0, &privkey.PublicKey, privkey0)
	return privkey,template,cert, certPEM, privKeyPEM
}

func writeFile(fileName string, caName []byte) {
	err := ioutil.WriteFile(rootPath+fileName, caName, 0644)
	if err != nil {
		return
	}
}

func verifyCa(rootCert, midCert, serverCert *x509.Certificate) {
	// openssl verify -CAfile RootCert.pem -untrusted Intermediate.pem UserCert.pem
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if serverCert != nil {
		inter := x509.NewCertPool()
		inter.AddCert(midCert)
		opts.Intermediates = inter
		if _, err := serverCert.Verify(opts); err != nil {
			checkErr(err)
		}
	} else {
		if _, err := midCert.Verify(opts); err != nil {
			checkErr(err)
		}
	}
	fmt.Println("Verify CA success")
}

func main() {
	_, err := os.Stat(rootPath)
	if err != nil {
		err = os.Mkdir("ssl", os.ModePerm)
		checkErr(err)
	}
	log.Printf("start to generate CA")
	rootPrivkey,rootTemplate,rootCert, rootPEM, rootPrivKeyPEM := certSetup(2, RootCommonName, 10, true,nil,nil)
	log.Printf("start to generate Mid CA")
	midPrivkey,midTemplate,midCert, midPEM, midPrivKeyPEM := certSetup(1, MidCommonName, 5, true,rootTemplate,rootPrivkey)
	log.Printf("start to generate server cert")
	_,_,serverCert, serverPEM, serverPrivKeyPEM := certSetup(0, host, 2, false,midTemplate,midPrivkey)

	writeFile("root.pem", rootPEM.Bytes())
	writeFile("rootkey.pem", rootPrivKeyPEM.Bytes())
	writeFile("mid.pem", midPEM.Bytes())
	writeFile("midkey.pem", midPrivKeyPEM.Bytes())
	log.Printf("start to verify midCert")
	verifyCa(rootCert, midCert, nil)
	writeFile("server.pem", serverPEM.Bytes())
	writeFile("serverkey.pem", serverPrivKeyPEM.Bytes())
	log.Printf("start to verify serverCert")
	verifyCa(rootCert, midCert, serverCert)
}