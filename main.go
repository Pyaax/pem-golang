package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// importPublicKeyFromPemFile is able to create a public key structure from a given .pem file.
// The function searches for the provided filename in the current directory.
func importPublicKeyFromPemFile(filename string) rsa.PublicKey {
	publcKeyFile, err := os.Open(filename)

	if err != nil {
		log.Fatalln("error while trying to open key file: ", err)
	}

	pemFileInfo, _ := publcKeyFile.Stat()
	var size int64 = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(publcKeyFile)

	_, err = buffer.Read(pemBytes)

	if err != nil {
		log.Fatalln("error while trying to read key file: ", err)
	}

	data, _ := pem.Decode([]byte(pemBytes))

	publcKeyFile.Close()

	publicKeyImported, err := x509.ParsePKCS1PublicKey(data.Bytes)

	if err != nil {
		log.Fatalln("error while trying to parse key file: ", err)
	}

	return *publicKeyImported
}

// importPrivateKeyFromPem is able to create a private key structure from a given .pem file.
// The function searches for the provided filename in the current directory.
func importPrivateKeyFromPem(filename string) rsa.PrivateKey {
	privateKeyFile, err := os.Open(filename)

	if err != nil {
		log.Fatalln("error while trying to open key file: ", err)
	}

	pemFileInfo, _ := privateKeyFile.Stat()
	var size int64 = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)

	_, err = buffer.Read(pemBytes)

	if err != nil {
		log.Fatalln("error while trying to read key file: ", err)
	}

	data, _ := pem.Decode([]byte(pemBytes))

	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		log.Fatalln("error while trying to parse key file: ", err)
	}

	return *privateKeyImported
}

func main() {
	publicKey := importPublicKeyFromPemFile("./keys/public.pem")
	privateKey := importPrivateKeyFromPem("./keys/private.pem")

	fmt.Printf("%d\n", publicKey.Size())
	fmt.Printf("%d\n", privateKey.Size())
}
