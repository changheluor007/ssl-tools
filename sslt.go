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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	. "ssl-tools/src"
	"strings"
	"time"
)

var (
	r, s, ro, rc, so, sc, c, h string
	help                       bool
	db                         = OpenDB()
)

func init() {
	flag.StringVar(&r, "r", "true", "Root_CA Model")
	flag.StringVar(&ro, "ro", "Google Trust Services LLC", "Specified Root Organization")
	flag.StringVar(&rc, "rc", "GTS Root R1", "Specified Root CommonName")
	flag.StringVar(&s, "s", "true", "Server_CA Model")
	flag.StringVar(&so, "so", "Google Trust Services LLC", "Specified Server Organization")
	flag.StringVar(&sc, "sc", "GTS CA 1C3", "Specified Server CommonName")
	flag.StringVar(&c, "c", "US", "Specified Country")
	flag.StringVar(&h, "h", "127.0.0.1", "Specified domain name")
	flag.BoolVar(&help, "help", false, "Display help information")
}
func main() {
	if help {
		flag.Usage()
	}
	//if r == "true" {
	//	certificate, caPEM, caPrivyKeyPEM, caPrivyKey := configuration(true, rc, ro, c, nil, nil, nil, nil)
	//}
	if s == "true" {
		rootCertificate, rootCAPEM, _, rootCAPrivyKey := configuration(true, rc, ro, c, nil, nil, nil, nil)
		_, serverCAPEM, serverCAPrivyKeyPEM, _ := configuration(false, sc, so, c, rootCertificate, rootCAPrivyKey, []net.IP{net.ParseIP(h)}, []string{h})

		serverCert, err := tls.X509KeyPair(serverCAPEM.Bytes(), serverCAPrivyKeyPEM.Bytes())
		CheckErr(err)

		serverTLSConf := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
		}

		certPool := x509.NewCertPool()
		// 从 DB 获取 rootCAPEM
		certPool.AppendCertsFromPEM(rootCAPEM.Bytes())
		clientTLSConf := &tls.Config{
			RootCAs: certPool,
		}
		testCA(serverTLSConf, clientTLSConf)
	}
}

func configuration(isCA bool, commonName string, organization string, country string, rootCertificate *x509.Certificate, rootPrivyKey *rsa.PrivateKey, host []net.IP, dnsName []string) (*x509.Certificate, *bytes.Buffer, *bytes.Buffer, *rsa.PrivateKey) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{country},
		},

		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IPAddresses:           host,
		DNSNames:              dnsName,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	// create our private and public key
	caPrivyKey, err := rsa.GenerateKey(rand.Reader, 4096)
	CheckErr(err)
	// create the CA
	if rootCertificate == nil {
		rootCertificate = certificate
	}
	if rootPrivyKey == nil {
		rootPrivyKey = caPrivyKey
	}
	fmt.Println("\nrootCertificate: ", &rootCertificate, "certificate: ", &certificate, "rootPrivyKey: ", &rootPrivyKey, "caPrivyKey: ", &caPrivyKey, "rootPrivyKey.PublicKey: ", "\n")
	caBytes, err := x509.CreateCertificate(rand.Reader, certificate, rootCertificate, &rootPrivyKey.PublicKey, caPrivyKey)
	CheckErr(err)

	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	CheckErr(err)

	caPrivyKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivyKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivyKey),
	})
	CheckErr(err)

	CANew(db, strings.Replace(commonName, " ", "_", -1), isCA, certificate, rootCertificate, caPrivyKey, rootPrivyKey, caPEM, caPrivyKeyPEM)
	return certificate, caPEM, caPrivyKeyPEM, caPrivyKey
}

func testCA(serverTLSConf *tls.Config, clientTLSConf *tls.Config) {
	// set up the httptest.Server using our certificate signed by our CA
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "success!")
		CheckErr(err)
	}))
	server.TLS = serverTLSConf
	server.StartTLS()
	defer server.Close()
	fmt.Println(server.URL)
	time.Sleep(time.Duration(10) * time.Second)

	// communicate with the server using a http.Client configured to trust our CA
	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}
	httpTEST := http.Client{
		Transport: transport,
	}
	resp, err := httpTEST.Get(server.URL)
	CheckErr(err)

	// verify the response
	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	CheckErr(err)
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "success!" {
		fmt.Println(body)
	} else {
		panic("not successful!")
	}
}
