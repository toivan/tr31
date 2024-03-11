package main

import (
	"fmt"
	"tr31/ed"
)

func main() {
	// Ключ шифрования PIN
	pinEncryptionKey := "3F419E1CB7079442AA37474C2EFBF8B8"
	// Пример ключа защиты блока ключей (Key Block Protection Key)
	keyBlockProtectionKeyHex := "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6"

	// Создание нового экземпляра TR31EncrypterDecrypter
	tr31ED := ed.NewTR31EncrypterDecrypter(keyBlockProtectionKeyHex)

	// Шифрование данных
	encryptedTR31block, err := tr31ED.Encrypt(pinEncryptionKey)
	if err != nil {
		fmt.Printf("Ошибка при шифровании: %s\n", err)
		return
	}
	fmt.Println("Complete Encrypted Key Block:", encryptedTR31block)

	// Дешифрование данных
	decryptedData, err := tr31ED.Decrypt(encryptedTR31block)
	if err != nil {
		fmt.Printf("Ошибка при дешифровании: %s\n", err)
		return
	}
	fmt.Println("Decrypted Data (PIN Encryption Key):", decryptedData)

}

/*Вывод программы:
Header Hex: 44303131325030414530304530303030
Header ASCII: D0112P0AE00E0000
Binary Key Data (hex): 00803f419e1cb7079442aa37474c2efbf8b81c2965473ce206bb855b01533782
Key Block Protection Key, KBPK: 88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6
Key Block Authentication Key: 4ef24317696213840451890756757e573e0673483888f9b7f9b7517827f95022
Block 0: 00000000000000000000000000000000
Block 1: 44303131325030414530304530303030
Block 2: 00803f419e1cb7079442aa37474c2efb
Block 3: f8b81c2965473ce206bb855b01533782
Key Block MAC: 7e8e31da05f7425509593d03a457dc34
Complete Encrypted Key Block: D0112P0AE00E0000b82679114f470f540165edfbf7e250fcea43f810d215f8d207e2e417c07156a27e8e31da05f7425509593d03a457dc34
Decrypted Data (PIN Encryption Key): 3f419e1cb7079442aa37474c2efbf8b8
*/
