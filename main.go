package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Generar un par de claves RSA de 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error al generar la clave privada:", err)
		return
	}

	// Crear un archivo para la clave privada en formato PEM
	privateFile, err := os.Create("private.pem")
	if err != nil {
		fmt.Println("Error al crear el archivo de clave privada:", err)
		return
	}
	defer privateFile.Close()

	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(privateFile, privateBlock); err != nil {
		fmt.Println("Error al escribir la clave privada en el archivo:", err)
		return
	}

	fmt.Println("Clave privada generada y guardada en private.pem")

	// Extraer la clave pública correspondiente
	publicKey := &privateKey.PublicKey

	// Crear un archivo para la clave pública en formato PEM
	publicFile, err := os.Create("public.pem")
	if err != nil {
		fmt.Println("Error al crear el archivo de clave pública:", err)
		return
	}
	defer publicFile.Close()

	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("Error al serializar la clave pública:", err)
		return
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	if err := pem.Encode(publicFile, publicBlock); err != nil {
		fmt.Println("Error al escribir la clave pública en el archivo:", err)
		return
	}

	fmt.Println("Clave pública generada y guardada en public.pem")

	// Mensaje de prueba a cifrar
	message := []byte("Hola, este es un mensaje de prueba.")

	// Cifrar el mensaje con la clave pública
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		fmt.Println("Error al cifrar el mensaje:", err)
		return
	}

	fmt.Println("Mensaje cifrado:", ciphertext)

	// Descifrar el mensaje con la clave privada
	decryptedMessage, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		fmt.Println("Error al descifrar el mensaje:", err)
		return
	}

	fmt.Println("Mensaje descifrado:", string(decryptedMessage))
}
