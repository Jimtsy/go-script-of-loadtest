package baifu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"
	//"github.com/go-xweb/log"
)

func mainccccc() {
	rk := genKey(8)
	log.Infof("%d %x\n", len(rk), rk)
	rk = []byte(hex.EncodeToString(rk))
	log.Infof("%d %x\n", len(rk), rk)
	rk, _ = hex.DecodeString(string(rk))
	log.Infof("%d %x\n", len(rk), rk)
	// rk, _ = hex.DecodeString(string(rk))
	// log.Printf("%X\n", bcd([]byte(string(rk))))
	// rk = []byte("1111111111111111") //genKey(16)

	// log.Printf("%X\n", hex.EncodeToString(rk))
	// log.Printf("%s\n", hex.EncodeToString([]byte(hex.EncodeToString(rk))))
	// tak, _ := hex.DecodeString("52E96994EE1F3291")
	// body := []byte("00000000")
	// sign, err := genMac(body, tak)
	// log.Printf("%s %v\n", []byte(string(sign)), err)

	// checkMK, err = DesEncrypt(make([]byte, 8), mk, ModeCBC, PaddingNone)
	// log.Printf("主密钥校验值: %X %v\n", checkMK[:4], err)
}

// func bcd(data []byte) []byte {
// 	out := make([]byte, len(data)/2+1)
// 	n, err := hex.Decode(out, data)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return out[:n]
// }

// func bcd2Ascii(data []byte) []byte {
// 	out := make([]byte, len(data)*2)
// 	n := hex.Encode(out, data)
// 	return out[:n]
// }

var (
	ivKey     = make([]byte, 8)
	ivMac     = make([]byte, 8)
	ivMessage = make([]byte, 8)
	ivStorage = make([]byte, 16)
)

//Mode ....
type Mode int

//加密模式
const (
	ModeECB = Mode(0)
	ModeCBC = Mode(1)
	// MODE_OFB       = 2
	// MODE_CFB       = 3
	// MODE_CTR       = 4
)

//Padding ....
type Padding int

//填充模式
const (
	PaddingNone  = Padding(0)
	PaddingZero  = Padding(1)
	PaddingPKCS5 = Padding(2)
	PaddingPKCS7 = Padding(3)
)

//DesEncrypt DES加密
func DesEncrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	//fmt.Println("DesEncrypt - ", key)
	block, err := des.NewCipher(key[0:8])
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if padding == PaddingZero {
		src = ZeroPadding(src, bs)
	} else if padding == PaddingPKCS5 {
		src = PKCS5Padding(src, bs)
	} else if padding == PaddingPKCS7 {
		src = PKCS7Padding(src, bs)
	}

	out := make([]byte, len(src))
	if mode == ModeECB {
		if len(src)%bs != 0 {
			return nil, fmt.Errorf("加密块必须是%v的倍数", bs)
		}
		dst := out
		for len(src) > 0 {
			block.Encrypt(dst, src[:bs])
			src = src[bs:]
			dst = dst[bs:]
		}
	} else if mode == ModeCBC {
		blockMode := cipher.NewCBCEncrypter(block, make([]byte, 8))
		blockMode.CryptBlocks(out, src)
	}
	return out, nil
}

//DesDecrypt DES解密
func DesDecrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	//fmt.Println("DesDecrypt - ", key)

	block, err := des.NewCipher(key[0:8])
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	out := make([]byte, len(src))
	if mode == ModeECB {
		dst := out
		if len(src)%bs != 0 {
			return nil, fmt.Errorf("解密块必须是%v的倍数", bs)
		}
		for len(src) > 0 {
			block.Decrypt(dst, src[:bs])
			src = src[bs:]
			dst = dst[bs:]
		}
	} else if mode == ModeCBC {
		blockMode := cipher.NewCBCDecrypter(block, make([]byte, 8))
		blockMode.CryptBlocks(out, src)
	}
	if padding == PaddingZero {
		out = ZeroUnPadding(out)
	} else if padding == PaddingPKCS5 {
		out = PKCS5UnPadding(out)
	} else if padding == PaddingPKCS7 {
		out = PKCS7Unpadding(out)
	}
	return out, nil
}

//TripleDesEncrypt 3DES加密
func TripleDesEncrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("密钥不合法，有效密钥长度不能小于112位")
	}
	if len(key)%8 != 0 {
		return nil, fmt.Errorf("非法的密钥块")
	}
	key1 := key[0:8]
	key2 := key[8:16]
	key3 := key1
	if len(key) >= 24 {
		key3 = key[16:24]
	}
	result, err := DesEncrypt(src, key1, mode, padding) //加密
	if err != nil {
		return nil, err
	}
	result, err = DesDecrypt(result, key2, mode, padding) //解密
	if err != nil {
		return nil, err
	}
	return DesEncrypt(result, key3, mode, padding) //加密
}

//TripleDesDecrypt 3DES解密
func TripleDesDecrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("密钥不合法，有效密钥长度不能小于112位")
	}
	if len(key)%8 != 0 {
		return nil, fmt.Errorf("非法的密钥块")
	}
	key1 := key[0:8]
	key2 := key[8:16]
	key3 := key1
	if len(key) >= 24 {
		key3 = key[16:24]
	}
	result, err := DesDecrypt(src, key1, mode, padding)
	if err != nil {
		return nil, err
	}
	result, err = DesEncrypt(result, key2, mode, padding)
	if err != nil {
		return nil, err
	}
	return DesDecrypt(result, key3, mode, padding)
}

//RSAEncrypt ....
func RSAEncrypt(random []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	data, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, random)
	if err != nil {
		return nil, err
	}
	return data, nil
}

//RSADecrypt ....
func RSADecrypt(random []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, random)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// //DesECBEncrypt ....
// func DesECBEncrypt(src, key []byte) ([]byte, error) {
// 	block, err := des.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	bs := block.BlockSize()
// 	src = ZeroPadding(src, bs)
// 	if len(src)%bs != 0 {
// 		return nil, errors.New("Need a multiple of the blocksize")
// 	}
// 	out := make([]byte, len(src))
// 	dst := out
// 	for len(src) > 0 {
// 		block.Encrypt(dst, src[:bs])
// 		src = src[bs:]
// 		dst = dst[bs:]
// 	}
// 	return out, nil
// }

// //DesECBDecrypt ....
// func DesECBDecrypt(src, key []byte) ([]byte, error) {
// 	block, err := des.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	out := make([]byte, len(src))
// 	dst := out
// 	bs := block.BlockSize()
// 	if len(src)%bs != 0 {
// 		return nil, errors.New("crypto/cipher: input not full blocks")
// 	}
// 	for len(src) > 0 {
// 		block.Decrypt(dst, src[:bs])
// 		src = src[bs:]
// 		dst = dst[bs:]
// 	}
// 	out = ZeroUnPadding(out)
// 	// out = PKCS5UnPadding(out)
// 	return out, nil
// }

// //DesCBCEncrypt ....
// func DesCBCEncrypt(origData, key []byte) ([]byte, error) {
// 	block, err := des.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	//origData = PKCS5Padding(origData, block.BlockSize())
// 	blockMode := cipher.NewCBCEncrypter(block, ivKey)
// 	crypted := make([]byte, len(origData))
// 	blockMode.CryptBlocks(crypted, origData)
// 	return crypted, nil
// }

// //DesCBCDecrypt ....
// func DesCBCDecrypt(crypted, key []byte) ([]byte, error) {
// 	block, err := des.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	blockMode := cipher.NewCBCDecrypter(block, ivKey)
// 	origData := make([]byte, len(crypted))
// 	blockMode.CryptBlocks(origData, crypted)
// 	//origData = PKCS5UnPadding(origData)
// 	return origData, nil
// }

//DesEncryptTMK ....
func DesEncryptTMK(mk, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key[0:8])
	if err != nil {
		return nil, err
	}
	dst := make([]byte, block.BlockSize())
	block.Encrypt(dst, mk)

	checkMK, err := DesEncrypt(ivKey, mk, ModeECB, PaddingNone)
	tmk := append(dst, checkMK[0:4]...)
	return tmk, nil
}

//AesCBCEncrypt ....
func AesCBCEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, 16))
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//AesCBCDecrypt ....
func AesCBCDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, make([]byte, 16))
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

//AesEncrypt ....
func AesEncrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key[0:24])
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if padding == PaddingZero {
		src = ZeroPadding(src, bs)
	} else if padding == PaddingPKCS5 {
		src = PKCS5Padding(src, bs)
	} else if padding == PaddingPKCS7 {
		src = PKCS7Padding(src, bs)
	}
	if mode == ModeCBC {
		blockMode := cipher.NewCBCEncrypter(block, make([]byte, 16))
		crypted := make([]byte, len(src))
		blockMode.CryptBlocks(crypted, src)
		return crypted, nil
	}
	return []byte{}, nil
}

//AesDecrypt ....
func AesDecrypt(src, key []byte, mode Mode, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key[0:24])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(src))
	if mode == ModeCBC {
		blockMode := cipher.NewCBCDecrypter(block, make([]byte, 16))
		blockMode.CryptBlocks(out, src)
	}

	if padding == PaddingZero {
		out = ZeroUnPadding(out)
	} else if padding == PaddingPKCS5 {
		out = PKCS5UnPadding(out)
	} else if padding == PaddingPKCS7 {
		out = PKCS7Unpadding(out)
	}
	return out, nil
}

//ZeroUnPadding ....
func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimRightFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

//PKCS5Padding ....
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//PKCS5UnPadding ....
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//ZeroPadding ....
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

//PKCS7Padding ....
func PKCS7Padding(b []byte, blocksize int) []byte {
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

//PKCS7Unpadding ....
func PKCS7Unpadding(b []byte) []byte {
	c := b[len(b)-1]
	n := int(c)
	// for i := 0; i < n; i++ {
	// 	if b[len(b)-n+i] != c {
	// 		return nil, ErrInvalidPKCS7Padding
	// 	}
	// }
	return b[:len(b)-n]
}

func getTransferableKeys(mk, key1, key2 []byte) ([]byte, error) {
	//加密key1
	block, err := des.NewCipher(mk[:8])
	if err != nil {
		log.Error(err)
		return nil, err
	}
	key1Bytes := make([]byte, block.BlockSize())
	block.Encrypt(key1Bytes, key1)
	//计算key1校验值
	checkValueCipher, err := des.NewCipher(key1[0:8])
	if err != nil {
		log.Error(err)
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(checkValueCipher, make([]byte, 8))
	checkvalue4key1 := make([]byte, 8)
	checkValue := make([]byte, 8)
	blockMode.CryptBlocks(checkvalue4key1, checkValue)
	key1Bytes = append(key1Bytes, checkvalue4key1[0:4]...)

	//加密key2
	key2Bytes := make([]byte, block.BlockSize())
	block.Encrypt(key2Bytes, key2)
	key1Bytes = append(key1Bytes, key2Bytes...)
	//计算key2校验值
	checkValueCipher2, err := des.NewCipher(key2[0:8])
	if err != nil {
		log.Error(err)
		return nil, err
	}
	blockMode2 := cipher.NewCBCEncrypter(checkValueCipher2, make([]byte, 8))
	checkvalue4key2 := make([]byte, 8)
	checkValue2 := make([]byte, 8)
	blockMode2.CryptBlocks(checkvalue4key2, checkValue2)
	key1Bytes = append(key1Bytes, checkvalue4key2[0:4]...)

	return key1Bytes, nil

}

func genMac(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// pad source data:
	paddedData := data
	padLen := block.BlockSize() - len(data)%block.BlockSize()
	if padLen != 0 {
		paddedData = append(paddedData, make([]byte, padLen)...)
	}

	// xor each 8 bytes:
	xorResult := make([]byte, block.BlockSize())
	for len(paddedData) > 0 {
		fastXORWords(xorResult, xorResult, paddedData[:block.BlockSize()])
		paddedData = paddedData[block.BlockSize():]
	}

	// hexadecimal encode xor result:
	hexResult := []byte(strings.ToUpper(hex.EncodeToString(xorResult)))

	// des encrypt first 8 bytes:
	block.Encrypt(hexResult, hexResult[:block.BlockSize()])

	// xor the first 8 bytes with the second 8 bytes:
	fastXORWords(xorResult, hexResult[:block.BlockSize()], hexResult[block.BlockSize():])

	block.Encrypt(xorResult, xorResult)
	//log.Printf("%s\n", strings.ToUpper(hex.EncodeToString(xorResult)))
	return []byte(strings.ToUpper(hex.EncodeToString(xorResult))[:8]), nil
}

// copied from crypto/cipher/xor.go
func fastXORWords(dst, a, b []byte) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	n := len(b) / int(unsafe.Sizeof(uintptr(0)))
	for i := 0; i < n; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}

func genKey(size int) []byte {
	key := make([]byte, size)
	rand.Read(key)
	return key
}

func encryptMsg(data, key []byte) []byte {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		log.Panic(err.Error)
	}

	// pad srource data:
	paddedData := data
	padLen := block.BlockSize() - len(data)%block.BlockSize()
	if padLen != 0 {
		paddedData = append(paddedData, make([]byte, padLen)...)
	}

	// ecb mode:
	cipherData := make([]byte, len(paddedData))
	ret := cipherData // keep the whole ref
	for len(paddedData) > 0 {
		block.Encrypt(cipherData, paddedData[:block.BlockSize()])
		cipherData = cipherData[block.BlockSize():]
		paddedData = paddedData[block.BlockSize():]
	}
	return ret
}

func decryptMsg(data, key []byte) []byte {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		log.Panic(err.Error())
	}

	if len(data)%block.BlockSize() != 0 {
		log.Panic("input not full blocks")
	}

	// ecb mode:
	cipherData := make([]byte, len(data))
	ret := cipherData // keep the whole ref
	for len(data) > 0 {
		block.Decrypt(cipherData, data[:block.BlockSize()])
		data = data[block.BlockSize():]
		cipherData = cipherData[block.BlockSize():]
	}
	return ret
}
func encryptKey(data, key []byte) []byte {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		log.Panic(err.Error())
	}

	// if len(data) != (block.BlockSize() + 4) {
	// 	log.Panic("bad key data")
	// }
	d := make([]byte, block.BlockSize())
	block.Encrypt(d, data[:8])
	return d
}
func decryptKey(data, key []byte) []byte {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		log.Panic(err.Error())
	}

	// if len(data) != (block.BlockSize() + 4) {
	// 	log.Panic("bad key data")
	// }
	d := make([]byte, block.BlockSize())
	block.Decrypt(d, data[:8])
	return d
}

func encryptRandom(key *rsa.PublicKey, random []byte) []byte {
	data, err := rsa.EncryptPKCS1v15(rand.Reader, key, random)
	if err != nil {
		log.Panic(err.Error())
	}
	return data
}
