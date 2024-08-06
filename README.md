# easycrypto

# support aes/rsa

# install
```
$ go get github.com/CodeSerenade/easycrypto
```

# about AES ECB
```
// AES-ECB encryption
encrypt,err := easycrypto.AESEncryptECB(plaintext, key)

// AES-ECB decryption
decrypt,err := easycrypto.AESDecryptECB(encrypt, key)
```

# about RSA PKCS1v15
```
// RSA PKCS1v15 encryption
encrypt,err := easycrypto.RSAEncrypt(plaintext, publicKey)

// RSA PKCS1v15 decryption
decrypt,err := easycrypto.RSADecrypt(encrypt, privateKey)
```

# about RSA SIGN
```
// RSA SIGN encryption
encrypt,err := easycrypto.RSASign(plaintext, privateKey)

// RSA SIGN decryption
decrypt,err := easycrypto.RSAVerify(plaintext, encrypt, publicKey)
```