package ed

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"tr31/block"
	"tr31/cmac"
)

// Header структура для хранения и управления заголовком TR-31.
type Header struct {
	KeyBlockVersionID      byte
	KeyBlockLength         [4]byte
	KeyUsage               [2]byte
	Algorithm              byte
	ModeOfUse              byte
	KeyVersionNumber       [2]byte
	Exportability          byte
	NumberOfOptionalBlocks [2]byte
	Reserved               [2]byte
}

// NewHeader создает и возвращает новый заголовок TR-31 с заданными параметрами.
func NewHeader(versionID byte, length [4]byte, usage [2]byte, algo, mode byte, version [2]byte, exportability byte, optionalBlocks, reserved [2]byte) *Header {
	return &Header{
		KeyBlockVersionID:      versionID,
		KeyBlockLength:         length,
		KeyUsage:               usage,
		Algorithm:              algo,
		ModeOfUse:              mode,
		KeyVersionNumber:       version,
		Exportability:          exportability,
		NumberOfOptionalBlocks: optionalBlocks,
		Reserved:               reserved,
	}
}

// ToBytes преобразует заголовок в слайс байтов.
func (h *Header) ToBytes() []byte {
	return []byte{
		h.KeyBlockVersionID,
		h.KeyBlockLength[0], h.KeyBlockLength[1], h.KeyBlockLength[2], h.KeyBlockLength[3],
		h.KeyUsage[0], h.KeyUsage[1],
		h.Algorithm,
		h.ModeOfUse,
		h.KeyVersionNumber[0], h.KeyVersionNumber[1],
		h.Exportability,
		h.NumberOfOptionalBlocks[0], h.NumberOfOptionalBlocks[1],
		h.Reserved[0], h.Reserved[1],
	}
}

// ToHex возвращает шестнадцатеричное представление заголовка.
func (h *Header) ToHex() string {
	return hex.EncodeToString(h.ToBytes())
}

// ToString возвращает строковое представление заголовка.
func (h *Header) ToString() string {
	return string(h.ToBytes())
}

// EncrypterDecrypter определяет интерфейс для шифрования и дешифрования данных.
type EncrypterDecrypter interface {
	Encrypt(data string) (string, error)
	Decrypt(data string) (string, error)
}

// TR31EncrypterDecrypter реализует интерфейс EncrypterDecrypter для стандарта TR-31.
type TR31EncrypterDecrypter struct {
	KBPK string // Key Block Protection Key
}

// NewTR31EncrypterDecrypter создает новый экземпляр TR31EncrypterDecrypter с заданными KBEK и MAC.
func NewTR31EncrypterDecrypter(kbpk string) *TR31EncrypterDecrypter {
	return &TR31EncrypterDecrypter{
		KBPK: kbpk,
	}
}

// Encrypt шифрует данные с использованием Key Block Encryption Key и MAC в качестве IV.
func (ed *TR31EncrypterDecrypter) Encrypt(pin string) (string, error) {
	pinEncryptionKey, _ := hex.DecodeString(pin)

	header := NewHeader(
		0x44,
		[4]byte{0x30, 0x31, 0x31, 0x32},
		[2]byte{0x50, 0x30},
		0x41,
		0x45,
		[2]byte{0x30, 0x30},
		0x45,
		[2]byte{0x30, 0x30},
		[2]byte{0x30, 0x30},
	)

	// Преобразование заголовка в hex-строку
	headerHex := header.ToHex()
	fmt.Printf("Header Hex: %s\n", headerHex)

	// Преобразование заголовка в ASCII-строку
	headerASCII := header.ToString()
	fmt.Printf("Header ASCII: %s\n", headerASCII)

	// Длина ключа в байтах (128 бит / 8 = 16 байт)
	keyLength := []byte{0x00, 0x80}

	// Случайное заполнение 14 байт
	padding := make([]byte, 14)
	_, err := rand.Read(padding)
	if err != nil {
		fmt.Println("Ошибка генерации случайного заполнения:", err)
		return "", nil
	}

	// Фейковый padding, соответсвующий спецификации стр.75 (для правильного расчета закомментировать)
	padding, _ = hex.DecodeString("1C2965473CE206BB855B01533782")

	// Конкатенация длины ключа, ключа шифрования PIN и заполнения
	binaryKeyData := append(keyLength, pinEncryptionKey...)
	binaryKeyData = append(binaryKeyData, padding...)

	fmt.Printf("Binary Key Data (hex): %s\n", hex.EncodeToString(binaryKeyData))

	keyBlockProtectionKey, _ := hex.DecodeString(ed.KBPK)
	fmt.Println("Key Block Protection Key, KBPK:", ed.KBPK)

	// Преобразование []byte в строку шестнадцатеричного формата
	keyBlockProtectionKeyStr := hex.EncodeToString(keyBlockProtectionKey)

	// Генерация подключей K1 и K2
	_, _, err = cmac.GenerateSubkeys(keyBlockProtectionKeyStr)
	if err != nil {
		fmt.Println("Ошибка при генерации подключей:", err)
		return "", nil
	}

	// Подключи K1 и K2
	// fmt.Printf("K1: %x\n", K1)
	// fmt.Printf("K2: %x\n", K2)

	// Генерация Key Block Encryption Key
	keyBlockEncryptionKey, err := block.GenerateKeyBlockEncryptionKeyFromKBPK(ed.KBPK)
	if err != nil {
		fmt.Println("Ошибка при генерации Key Block Encryption Key:", err)
		return "", nil
	}

	// Генерация Key Block Authentication Key
	keyBlockAuthKey, err := block.GenerateKeyBlockAuthenticationKeyFromKBPK(ed.KBPK)
	if err != nil {
		fmt.Println("Ошибка при генерации Key Block Authentication Key:", err)
		return "", nil
	}

	// Использования Key Block Authentication Key для генерации S и KM1
	_, KM1 := cmac.CalculateSAndKM1(keyBlockAuthKey)

	// fmt.Printf("S: %x\n", S)
	// fmt.Printf("KM1: %x\n", KM1)

	// Генерация MAC data blocks
	macDataBlocks := cmac.GenerateMACDataBlocks(header.ToBytes(), binaryKeyData)
	for i, macDataBlock := range macDataBlocks {
		fmt.Printf("Block %d: %x\n", i, macDataBlock)
	}

	// Вычисление MAC
	keyBlockMac, err := cmac.CalculateMAC(macDataBlocks, keyBlockAuthKey, KM1)
	if err != nil {
		fmt.Println("Ошибка при вычислении MAC:", err)
		return "", nil
	}
	fmt.Printf("Key Block MAC: %x\n", keyBlockMac)

	// Шифрование данных с использованием Key Block Encryption Key и MAC в качестве IV
	dataToEncrypt := append(keyLength, pinEncryptionKey...) // 16 байт длина ключа + ключ шифрования PIN
	dataToEncrypt = append(dataToEncrypt, padding...)       // добавление padding

	encryptedData, err := cmac.EncryptAESCBC(dataToEncrypt, keyBlockEncryptionKey, hex.EncodeToString(keyBlockMac))
	if err != nil {
		fmt.Printf("Ошибка при шифровании: %s\n", err)
		return "", nil
	}

	// Конструирование полного зашифрованного ключевого блока
	completeKeyBlock := headerASCII + encryptedData + hex.EncodeToString(keyBlockMac)
	return completeKeyBlock, nil
}

// Decrypt дешифрует данные с использованием Key Block Encryption Key и MAC в качестве IV.
func (ed *TR31EncrypterDecrypter) Decrypt(data string) (string, error) {
	// Проверка минимальной длины данных
	if len(data) < 32 { // Минимальная длина заголовка и MAC
		return "", fmt.Errorf("неверный формат данных")
	}

	// Разбиение данных на заголовок, зашифрованный блок и MAC
	// headerASCII := data[:16]
	encryptedBlock := data[16 : len(data)-32]
	receivedMAC := data[len(data)-32:]

	/*	fmt.Printf("Header ASCII: %s\n", headerASCII)
		fmt.Printf("Encrypted Block: %s\n", encryptedBlock)
		fmt.Printf("Received MAC: %s\n", receivedMAC)*/

	// Генерация Key Block Encryption Key
	keyBlockEncryptionStr, err := block.GenerateKeyBlockEncryptionKeyFromKBPK(ed.KBPK)
	if err != nil {
		fmt.Println("Ошибка при генерации Key Block Encryption Key:", err)
		return "", err
	}

	// Дешифрование данных
	decryptedData, err := cmac.DecryptAESCBC(encryptedBlock, keyBlockEncryptionStr, receivedMAC)
	if err != nil {
		fmt.Println("Ошибка при дешифровании:", err)
		return "", err
	}

	pinKey, err := extractPinEncryptionKey(hex.EncodeToString(decryptedData))
	if err != nil {
		fmt.Println("Ошибка при извлечении:", err)
		return "", err
	}

	return pinKey, nil
}

func extractPinEncryptionKey(hexData string) (string, error) {
	if len(hexData) < 36 { // 4 символа для первых двух байтов + 32 символа для ключа
		return "", fmt.Errorf("шестнадцатеричная строка слишком короткая")
	}

	// Первые два байта (4 символа) пропускаем, затем берем следующие 32 символа (16 байт)
	pinEncryptionKey := hexData[4:36]

	return pinEncryptionKey, nil
}
