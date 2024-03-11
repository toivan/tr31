package libs

// XorBytes функция XOR
func XorBytes(a, b []byte) []byte {
	result := make([]byte, len(b))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
