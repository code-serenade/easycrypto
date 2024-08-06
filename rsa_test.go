package easycrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

var (
	pub, privPKCS8 string
)

func init() {
	pub, privPKCS8, _, _ = CreateKeyPair()

}

type randReaderFunc func(b []byte) (n int, err error)

func (f randReaderFunc) Read(b []byte) (n int, err error) {
	return f(b)
}

func TestRSA(t *testing.T) {
	pub, privPKCS8, privPKCS1, err := CreateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("pub %v\n", pub)
	fmt.Printf("privPKCS8 %v\n", privPKCS8)
	data := []byte("hello world")
	enc, err := RSAEncrypt([]byte(pub), data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := RSADecrypt([]byte(privPKCS8), enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(data) {
		t.Fatal("not equal")
	}
	fmt.Printf("dec %v\n", string(dec))

	sign, err := RSASign([]byte(privPKCS1), data)
	if err != nil {
		t.Fatal(err)
	}
	err = RSAVerify([]byte(pub), data, sign)
	if err != nil {
		t.Fatal(err)
	}

	err = RSAVerify([]byte(pub), data, "")
	if err == nil {
		t.Fatalf("should error")
	}
	fmt.Printf("RSAVerify err %v\n", err)

	//test err

	// rand.Reader
	randReaderFunc := randReaderFunc(func(b []byte) (n int, err error) {
		return 0, fmt.Errorf("rand error")
	})

	origin := rand.Reader
	rand.Reader = randReaderFunc

	_, _, _, err = CreateKeyPair()
	if err == nil {
		t.Fatalf("should error")
	}
	rand.Reader = origin
	defaultBits = -1
	_, _, _, err = CreateKeyPair()
	if err == nil {
		t.Fatalf("should error")
	}
}

func TestRSAEncrypt(t *testing.T) {
	data := []byte("test data")
	encryptedData, err := RSAEncrypt([]byte(pub), data)
	if err != nil {
		t.Errorf("RSAEncryptRSAEncrypt: %v", err)
	}
	invalidPubKey := []byte("invalidPubKey")
	_, err = RSAEncrypt(invalidPubKey, data)
	if err == nil {
		t.Errorf("RSAEncrypt should return error for invalid public key")
	}

	decryptedData, err := RSADecrypt([]byte(privPKCS8), encryptedData)
	if err != nil {
		t.Errorf("RSADecrypt error: %v", err)
	}
	if string(decryptedData) != string(data) {
		t.Errorf("not equal")
	}

	// test error

	invalidPEM := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhk...
-----END PUBLIC KEY-----`)

	_, err = RSAEncrypt(invalidPEM, data)
	if err == nil {
		t.Errorf("RSAEncrypt should return error for invalid public key")
	}
	fmt.Println(err)
}

func TestEncryptWithPublicKey(t *testing.T) {
	// 生成 RSA 密钥对用于测试
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 生成有效的 PEM 编码公钥
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	tests := []struct {
		name    string
		pubKey  []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Invalid PEM data",
			pubKey:  []byte("invalid pem data"),
			data:    []byte("test data"),
			wantErr: true,
		},
		{
			name:    "Valid PEM but invalid key",
			pubKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid key data")}),
			data:    []byte("test data"),
			wantErr: true,
		},
		{
			name:    "Valid PEM and valid key",
			pubKey:  validPEM,
			data:    []byte("test data"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RSAEncrypt(tt.pubKey, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptWithPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRSASignAndVerify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})

	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	tests := []struct {
		name        string
		privKey     []byte
		pubKey      []byte
		data        []byte
		wantErrSign bool
		wantErrVer  bool
	}{
		{
			name:        "Valid keys and data",
			privKey:     privPEM,
			pubKey:      pubPEM,
			data:        []byte("test data"),
			wantErrSign: false,
			wantErrVer:  false,
		},
		{
			name:        "Invalid private key PEM",
			privKey:     []byte("invalid pem data"),
			pubKey:      pubPEM,
			data:        []byte("test data"),
			wantErrSign: true,
			wantErrVer:  true, // No signature to verify
		},
		{
			name:        "Invalid public key PEM",
			privKey:     privPEM,
			pubKey:      []byte("invalid pem data"),
			data:        []byte("test data"),
			wantErrSign: false,
			wantErrVer:  true,
		},
		{
			name:        "Corrupted signature",
			privKey:     privPEM,
			pubKey:      pubPEM,
			data:        []byte("test data"),
			wantErrSign: false,
			wantErrVer:  true, // Will fail because we will modify the signature later
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sign, err := RSASign(tt.privKey, tt.data)
			if (err != nil) != tt.wantErrSign {
				t.Errorf("RSASign() error = %v, wantErr %v", err, tt.wantErrSign)
			}

			if tt.name == "Corrupted signature" {
				sign = "corrupted" + sign // Corrupt the signature
			}

			err = RSAVerify(tt.pubKey, tt.data, sign)
			if (err != nil) != tt.wantErrVer {
				t.Errorf("RSAVerify() error = %v, wantErr %v", err, tt.wantErrVer)
			}
		})
	}
}

func TestRSADecrypt(t *testing.T) {

	invalidPrivKey := []byte("invalid private key")

	encryptedData, _ := RSAEncrypt([]byte(pub), []byte("test data"))

	decryptedData, err := RSADecrypt([]byte(privPKCS8), encryptedData)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if decryptedData == nil {
		t.Errorf("Expected decrypted data, but got nil")
	}

	_, err = RSADecrypt(invalidPrivKey, encryptedData)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}
