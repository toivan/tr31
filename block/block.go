package block

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"tr31/cmac"
	"tr31/libs"
)

// GenerateKeyBlockEncryptionKey выполняет XOR и шифрование ECB.
func GenerateKeyBlockEncryptionKey(K2 []byte, kbKey string) ([]byte, error) {

	// Преобразование Key Block Protection Key из строки в байты
	kbKeyBytes, err := hex.DecodeString(kbKey)
	if err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(kbKeyBytes)
	if err != nil {
		return nil, err
	}

	// Дополнение данных до размера блока AES
	derivationData1 := padToBlockSize([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x80}, 16)
	derivationData2 := padToBlockSize([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x80}, 16)

	// Выполнение XOR операции и шифрования
	K2XORData1 := libs.XorBytes(K2, derivationData1)
	K2XORData2 := libs.XorBytes(K2, derivationData2)

	encryptedData1 := make([]byte, cipher.BlockSize())
	encryptedData2 := make([]byte, cipher.BlockSize())

	cipher.Encrypt(encryptedData1, K2XORData1)
	cipher.Encrypt(encryptedData2, K2XORData2)

	// Объединение зашифрованных данных для получения ключа шифрования блока
	keyBlockEncryptionKey := append(encryptedData1, encryptedData2...)

	return keyBlockEncryptionKey, nil
}

func padToBlockSize(data []byte, blockSize int) []byte {
	if len(data) == blockSize {
		return data
	}
	padded := make([]byte, blockSize)
	copy(padded, data)
	return padded
}

// GenerateKeyBlockAuthenticationKey Функция для генерации Key Block Authentication Key
func GenerateKeyBlockAuthenticationKey(K2 []byte, kbKey string) ([]byte, error) {
	//
	kbKeyBytes, err := hex.DecodeString(kbKey)
	if err != nil {
		return nil, fmt.Errorf("invalid format for Key Block Protection Key: %v", err)
	}

	// Создание шифратора
	cipher, err := aes.NewCipher(kbKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Проверка длины блока
	if len(K2) != cipher.BlockSize() {
		return nil, fmt.Errorf("key K2 is not the correct block size: %d bytes", cipher.BlockSize())
	}

	// Дополнение данных до размера блока AES
	derivationData1 := padToBlockSize([]byte{0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00, 0x80}, 16)
	derivationData2 := padToBlockSize([]byte{0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00, 0x80}, 16)

	// XOR K2 и данными для вычисления Key Block Authentication Key
	xorResult1 := libs.XorBytes(K2, derivationData1)
	xorResult2 := libs.XorBytes(K2, derivationData2)

	//
	encryptedPart1 := make([]byte, cipher.BlockSize())
	encryptedPart2 := make([]byte, cipher.BlockSize())
	cipher.Encrypt(encryptedPart1, xorResult1)
	cipher.Encrypt(encryptedPart2, xorResult2)

	// Соединение зашифрованных данных для получения Key Block Authentication Key
	keyBlockAuthenticationKey := append(encryptedPart1, encryptedPart2...)

	return keyBlockAuthenticationKey, nil
}

func GenerateKeyBlockEncryptionKeyFromKBPK(KBPK string) (string, error) {
	// Генерация подключей K1 и K2
	_, K2, err := cmac.GenerateSubkeys(KBPK)
	if err != nil {
		return "", fmt.Errorf("ошибка при генерации подключей: %v", err)
	}

	// Генерация Key Block Encryption Key
	keyBlockEncryptionKey, err := GenerateKeyBlockEncryptionKey(K2, KBPK)
	if err != nil {
		return "", fmt.Errorf("ошибка при генерации Key Block Encryption Key: %v", err)
	}

	return hex.EncodeToString(keyBlockEncryptionKey), nil
}

func GenerateKeyBlockAuthenticationKeyFromKBPK(KBPK string) ([]byte, error) {
	// Генерация подключей K1 и K2
	_, K2, err := cmac.GenerateSubkeys(KBPK)
	if err != nil {
		fmt.Println("Ошибка при генерации подключей:", err)
		return nil, err
	}

	// Генерация Key Block Authentication Key
	keyBlockAuthKey, err := GenerateKeyBlockAuthenticationKey(K2, KBPK)
	if err != nil {
		fmt.Println("Ошибка при генерации Key Block Authentication Key:", err)
		return nil, err
	}
	fmt.Println("Key Block Authentication Key:", hex.EncodeToString(keyBlockAuthKey))

	return keyBlockAuthKey, nil
}
