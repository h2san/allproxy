package allproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	iv   []byte
	info *cipherInfo
}

func (c *Cipher) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	if err != nil {
		fmt.Println(err)
	}
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

func NewCipher(method, password string) (c *Cipher, err error) {
	if password == "" {
		return nil, errors.New("empty key")
	}
	ci, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}
	key := evpBytesToKey(password, ci.keyLen)
	c = &Cipher{key: key, info: ci}
	return c, nil
}

var cipherMethod = map[string]*cipherInfo{
	"aes-256-cfb": {32, 16, newAESCFBStream},
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

func evpBytesToKey(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}
