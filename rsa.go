package easycrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

var (
	defaultBits = 2048
)

func CreateKeyPair() (pub, privPKCS8, privPKCS1 string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultBits)
	if err != nil {
		return
	}
	publicKey := &privateKey.PublicKey
	// 序列化私钥为PKCS1格式字符串
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})
	privPKCS1 = string(privateKeyPem)
	// 序列化公钥为字符串
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyBytes})
	pub = string(publicKeyPem)

	// 序列化私钥为PKCS8格式字符串
	privateKeyPKCS8, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privateKeyPemPKCS8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPKCS8})
	privPKCS8 = string(privateKeyPemPKCS8)
	return
}

// RSAEncrypt encrypts the given data with the provided PEM-encoded RSA public key.
func RSAEncrypt(pubKey []byte, data []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, fmt.Errorf("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// RSADecrypt decrypts the given data with the provided PEM-encoded RSA private key.
func RSADecrypt(privKey []byte, data []byte) ([]byte, error) {
	block, _ := pem.Decode(privKey)
	if block == nil {
		return nil, fmt.Errorf("private key error")
	}
	var priv *rsa.PrivateKey
	var err error

	// 尝试解析 PKCS#1 私钥
	priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 如果 PKCS#1 解析失败，尝试解析 PKCS#8 私钥
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		priv, ok = privInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, data)
}

// RSASign signs the given data with the provided PEM-encoded RSA private key.
func RSASign(privKey []byte, data []byte) (sign string, err error) {
	hash := crypto.SHA256
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(privKey)
	if block == nil {
		err = fmt.Errorf("private key error")
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed)
	if err != nil {
		return
	}
	sign = base64.StdEncoding.EncodeToString(signature)
	return
}

// RSAVerify verifies the given base64-encoded signature with the provided PEM-encoded RSA public key.
func RSAVerify(pubKey, data []byte, base64Sign string) error {
	hash := crypto.SHA256
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return fmt.Errorf("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)

	sign, err := base64.StdEncoding.DecodeString(base64Sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pub, hash, hashed, sign)
}

// func FormatRSAPublicKey(public string) string {
// 	if !strings.Contains(public, "-----BEGIN RSA PUBLIC KEY-----") {
// 		// 添加头
// 		public = fmt.Sprintf("-----BEGIN RSA PUBLIC KEY-----\n%s", public)
// 	}
// 	if !strings.Contains(public, "-----END RSA PUBLIC KEY-----") {
// 		// 添加尾
// 		public = fmt.Sprintf("%s\n-----END RSA PUBLIC KEY-----", public)
// 	}
// 	return public
// }

// func FormatRSAPrivKey(priv string) string {
// 	if !strings.Contains(priv, "-----BEGIN RSA PRIVATE KEY-----") {
// 		// 添加头
// 		priv = fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s", priv)
// 	}
// 	if !strings.Contains(priv, "-----END RSA PRIVATE KEY-----") {
// 		// 添加尾
// 		priv = fmt.Sprintf("%s\n-----END RSA PRIVATE KEY-----", priv)
// 	}
// 	return priv
// }
