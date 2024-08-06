package easycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// return base64 string
func EncryptCTR(key, nonce, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(message))
	stream.XORKeyStream(ciphertext, message)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// enter base64 string
func DecryptCTR(key, nonce []byte, ciphertextBase64 string) ([]byte, error) {
	// Decode the base64 encoded message
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}
	// 创建并初始化 AES 解密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 创建 CTR 解密模式
	stream := cipher.NewCTR(block, nonce)

	// 解密数据
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	// 返回解密后的数据
	return plaintext, nil
}

// AES encrypt using ECB mode
func AESEncryptECB(plainText string, aesKey []byte) (string, error) {
	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Pad the plain text
	padded := pad([]byte(plainText))

	// Encrypt the padded data
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(encrypted[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}

	// Return the base64-encoded encrypted data
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// AES decrypt using ECB mode
func AESDecryptECB(cipherText string, aesKey []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Decode the base64-encoded input
	decoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	// Decrypt the input data
	decrypted := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], decoded[i:i+aes.BlockSize])
	}

	// Unpad the decrypted data
	unpadded := unpad(decrypted)

	// Return the decrypted plaintext
	return unpadded, nil
}

// PKCS7 padding implementation
func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7 unpadding implementation
func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
