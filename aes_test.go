package easycrypto

import (
	"fmt"
	"testing"
)

func TestEncryptCTR(t *testing.T) {
	// test error
	_, err := EncryptCTR([]byte{}, []byte{}, []byte{})
	if err == nil {
		t.Errorf("Expected error, got nil")
		return
	}
	_, err = DecryptCTR([]byte{}, []byte{}, "123")
	if err == nil {
		t.Errorf("Expected error, got nil")
		return
	}
	_, err = DecryptCTR([]byte{}, []byte{}, "")
	if err == nil {
		t.Errorf("Expected error, got nil")
		return
	}

	key := []byte("0123456789ABCDEF")
	nonce := []byte("0123456789ABCDEF")
	message := []byte("Hello, World!")

	encrypted, err := EncryptCTR(key, nonce, message)
	if err != nil {
		t.Errorf("Encryption error: %v", err)
		return
	}

	decrypted, err := DecryptCTR(key, nonce, encrypted)
	if err != nil {
		t.Errorf("Decryption error: %v", err)
		return
	}

	fmt.Println("decrypted-->", string(decrypted))

	// check
	if string(decrypted) != string(message) {
		t.Errorf("Decryption result mismatch")
		return
	}
}

func TestAESEncryptECB(t *testing.T) {
	// normal test
	plainText := "Hello, World!"
	aesKey := []byte("1234567890123456")

	encrypted, err := AESEncryptECB(plainText, aesKey)
	if err != nil {
		t.Errorf("AESEncryptECB error: %v", err)
	}

	// check
	decrypted, err := AESDecryptECB(encrypted, aesKey)
	if err != nil {
		t.Errorf("AESDecryptECB error: %v", err)
	}

	if string(decrypted) != plainText {
		t.Errorf("Decrypted text does not match plain text")
	}

	invalidKey := []byte("12345")
	_, err = AESEncryptECB(plainText, invalidKey)
	if err == nil {
		t.Errorf("Expected error for invalid key length, but got none")
	}
	_, err = AESDecryptECB(plainText, invalidKey)
	if err == nil {
		t.Errorf("Expected error for invalid key length, but got none")
	}
	_, err = AESDecryptECB("plainText", []byte("1234567890123456"))
	if err == nil {
		t.Errorf("Expected error for invalid key length, but got none")
	}

	// empty
	emptyPlainText := ""
	_, err = AESEncryptECB(emptyPlainText, aesKey)
	if err != nil {
		t.Errorf("AESEncryptECB error with empty plain text: %v", err)
	}

}
