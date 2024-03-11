package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"tr31/libs"
)

// leftShiftOneBit сдвигает байты влево на один байт
func leftShiftOneBit(in []byte) []byte {
	result := make([]byte, len(in))
	copy(result, in)

	overflow := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		newOverflow := in[i] >> 7
		result[i] = in[i]<<1 | overflow
		overflow = newOverflow
	}

	if in[0]&0x80 != 0 {
		result[len(in)-1] ^= 0x87
	}

	return result
}

// GenerateSubkeys генерирует два подключа к AES-256.
func GenerateSubkeys(key string) ([]byte, []byte, error) {
	if len(key) != 64 { // Проверка длины ключа (должен быть 256-битным для AES-256)
		return nil, nil, errors.New("key must be 256 bits (64 hex characters) long")
	}

	keyBlock, err := hex.DecodeString(key)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(keyBlock)
	if err != nil {
		return nil, nil, err
	}

	// Шифрование нулевого блока в режиме ECB для получения S
	zeroBlock := make([]byte, block.BlockSize())
	S := make([]byte, block.BlockSize())
	block.Encrypt(S, zeroBlock)

	// Печать промежуточного значения S
	// fmt.Printf("S: %x\n", S)

	K1beforeXOR := leftShiftOneBit(S)
	if S[0]&0x80 != 0 {
		K1beforeXOR[len(K1beforeXOR)-1] ^= 0x87
	}
	// fmt.Printf("K1beforeXOR: %x\n", K1beforeXOR)

	// Генерация K1 и K2 с использованием K1beforeXOR
	K1 := libs.XorBytes(K1beforeXOR, []byte{15: 0x87})

	K2beforeXOR := leftShiftOneBit(K1)
	if K1[0]&0x80 != 0 {
		K2beforeXOR[len(K2beforeXOR)-1] ^= 0x87
	}
	// fmt.Printf("K2beforeXOR: %x\n", K2beforeXOR)

	K2 := libs.XorBytes(K2beforeXOR, []byte{15: 0x87})

	return K1, K2, nil
}

// CalculateSAndKM1 Функция для вычисления S и KM1
func CalculateSAndKM1(key []byte) ([]byte, []byte) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("Ошибка создания шифра: %v", err))
	}
	zeroBlock := make([]byte, cipher.BlockSize())
	S := make([]byte, cipher.BlockSize())
	cipher.Encrypt(S, zeroBlock)

	K1 := leftShiftOneBit(S)
	if S[0]&0x80 != 0 {
		K1[len(K1)-1] ^= 0x87 // XOR с константой Rb
	}

	constant := make([]byte, cipher.BlockSize())
	constant[len(constant)-1] = 0x87 // Установка последнего байта в 0x87
	KM1 := libs.XorBytes(K1, constant)

	return S, KM1
}

// GenerateMACDataBlocks Функция для генерации MAC data blocks на основе заголовка и данных ключа.
func GenerateMACDataBlocks(header, keyData []byte) [][]byte {
	// Размер блока для AES — 16 байт.
	blockSize := aes.BlockSize

	// Создание IV (здесь просто нулевой блок, но он может быть любым или генерироваться).
	IV := make([]byte, blockSize)

	// Конкатенация IV, заголовка и данных ключа.
	fullData := append(IV, header...)
	fullData = append(fullData, keyData...)

	// Разделение полных данных на блоки по 16 байт.
	var blocks [][]byte
	for len(fullData) > 0 {
		block := make([]byte, blockSize)
		n := copy(block, fullData)
		blocks = append(blocks, block)
		fullData = fullData[n:]
	}

	// Возвращаем слайс блоков данных для MAC.
	return blocks
}

// CalculateMAC вычисляет MAC по блокам данных, используя Key Block Authentication Key и K1.
func CalculateMAC(blocks [][]byte, keyBlockAuthKey, KM1 []byte) ([]byte, error) {
	if len(blocks) < 1 {
		return nil, fmt.Errorf("no data blocks provided")
	}

	cipher, err := aes.NewCipher(keyBlockAuthKey)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	var previousEncryptedBlock []byte
	for i, block := range blocks {
		if i == 0 {
			previousEncryptedBlock = block
			continue
		}

		// Выполнение операции XOR между текущим блоком и предыдущим зашифрованным блоком.
		xoredBlock := libs.XorBytes(block, previousEncryptedBlock)

		// Если это предпоследний блок, применяем KM1.
		if i == len(blocks)-1 {
			xoredBlock = libs.XorBytes(xoredBlock, KM1)
		}

		// Шифрование результата XOR.
		encryptedBlock := make([]byte, aes.BlockSize)
		cipher.Encrypt(encryptedBlock, xoredBlock)

		// Обновление 'previousEncryptedBlock' для следующей итерации.
		previousEncryptedBlock = encryptedBlock
	}

	// Возвращаем последний зашифрованный блок, который теперь является MAC.
	return previousEncryptedBlock, nil
}

// EncryptAESCBC шифрует данные с использованием AES CBC.
func EncryptAESCBC(data []byte, kbekHex, ivHex string) (string, error) {
	// Преобразование KBЕК и IV из шестнадцатеричной строки в байты.
	kbek, err := hex.DecodeString(kbekHex)
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", err
	}

	// Создание шифра AES.
	block, err := aes.NewCipher(kbek)
	if err != nil {
		return "", err
	}

	// Создание CBC шифратора с использованием IV.
	mode := cipher.NewCBCEncrypter(block, iv)

	// Проверка, что данные кратны размеру блока.
	if len(data)%(2*aes.BlockSize) != 0 {
		return "", errors.New("данные не кратны двум размерам блока AES")
	}

	// Разделение данных на две части.
	firstHalf := data[:len(data)/2]
	secondHalf := data[len(data)/2:]

	// Шифрование каждой половины данных.
	ciphertextFirstHalf := make([]byte, len(firstHalf))
	ciphertextSecondHalf := make([]byte, len(secondHalf))
	mode.CryptBlocks(ciphertextFirstHalf, firstHalf)
	mode.CryptBlocks(ciphertextSecondHalf, secondHalf)

	// Объединение зашифрованных половин.
	fullCiphertext := append(ciphertextFirstHalf, ciphertextSecondHalf...)

	// Зашифрованные данные в шестнадцатеричном формате.
	return hex.EncodeToString(fullCiphertext), nil
}

// DecryptAESCBC decrypts data encrypted using AES CBC.
func DecryptAESCBC(encryptedHex, kbekHex, ivHex string) ([]byte, error) {
	// Преобразование зашифрованных данных, KBЕК и IV из шестнадцатеричной строки в байты.
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, err
	}
	kbek, err := hex.DecodeString(kbekHex)
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, err
	}

	// Создание шифра AES.
	block, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, err
	}

	// Создание CBC дешифратора с использованием IV.
	mode := cipher.NewCBCDecrypter(block, iv)

	// Проверка, что данные кратны размеру блока.
	if len(encryptedData)%(2*aes.BlockSize) != 0 {
		return nil, errors.New("зашифрованные данные не кратны двум размерам блока AES")
	}

	// Разделение данных на две части.
	firstHalf := encryptedData[:len(encryptedData)/2]
	secondHalf := encryptedData[len(encryptedData)/2:]

	// Расшифровка каждой половины данных.
	plaintextFirstHalf := make([]byte, len(firstHalf))
	plaintextSecondHalf := make([]byte, len(secondHalf))
	mode.CryptBlocks(plaintextFirstHalf, firstHalf)
	mode.CryptBlocks(plaintextSecondHalf, secondHalf)

	// Объединение расшифрованных половин.
	fullPlaintext := append(plaintextFirstHalf, plaintextSecondHalf...)

	return fullPlaintext, nil
}
