package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"reflect"
	"time"
)

var ShellFolder, _ = os.Getwd()
var host = flag.String("hostname", "localhost", "Specified domain name")

var commonName = flag.String("commonname","GTS Root R1", "Specified commonName")
var rootPath = ShellFolder + "/ssl/"
var author = "XRSec"

func main() {
	// get our ca and server certificate
	fmt.Println("Welcome to Use SSLTools\nAuthor: " + author)
	flag.Parse()
	errs := certSetup()
	if errs != nil {
		panic("Error Generate CA" + errs.Error())
	} else {
		fmt.Println("Success Generate CA")
	}
	rootCa := readFile("RootCA.pem")
	rootCaKey := readFile("RootCA_Key.pem")
	keyPair(rootCa, rootCaKey)
	rootCaCert := readFile("RootCA_Cert.pem")
	rootCaCertKey := readFile("RootCA_Cert_Key.pem")
	keyPair(rootCaCert, rootCaCertKey)
}

func readFile(fileName string) []byte {
	rootCa, err := ioutil.ReadFile(rootPath + fileName)

	if err != nil {
		panic("Error read " + fileName + err.Error())
	} else {
		fmt.Println("Success Generate " + fileName)
	}
	return rootCa
}

func writeFile(fileName string, caName []byte) {
	err := ioutil.WriteFile(rootPath+fileName, caName, 0644)
	if err != nil {
		return
	}
}

func keyPair(ca, caKey []byte) {
	var rootCa, err = tls.X509KeyPair(ca, caKey)
	if err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
	if rootCa.Leaf, err = x509.ParseCertificate(rootCa.Certificate[0]); err != nil {
		panic("Error parsing builtin CA " + err.Error())
	}
}

func certSetup() (err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			CommonName:   *commonName,
			Organization: []string{"Google Trust Services LLC"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return err
	}

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			CommonName: *host,
			//Organization:  []string{*Organization},
			//Country:       []string{*Country},
			//Province:      []string{*Province},
			//Locality:      []string{*Locality},
			//StreetAddress: []string{*StreetAddress},
			//PostalCode:    []string{*PostalCode},
			//OrganizationalUnit: []string{*OrganizationalUnit},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// IP Domain
	if net.ParseIP(*host) == nil {
		cert.DNSNames = append(cert.DNSNames, *host)
	} else {
		cert.IPAddresses = append(cert.IPAddresses, net.ParseIP(*host))
	}
	if err != nil {
		log.Println(err)
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	//if err != nil {
	// return nil, nil, err
	//}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	//if err != nil {
	// return nil, nil, err
	//}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return err
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	// export CA cert
	err = os.Mkdir("ssl", os.ModePerm)
	if err != nil {
		return err
	}

	writeFile("RootCA.pem", caPEM.Bytes())
	writeFile("RootCA_Key.pem", caPrivKeyPEM.Bytes())
	writeFile("RootCA_Cert.pem", certPEM.Bytes())
	writeFile("RootCA_Cert_Key.pem", certPrivKeyPEM.Bytes())
	fmt.Println("type:", reflect.TypeOf(caPEM.Bytes()))
	if err != nil {
		return
	}
	return
}
