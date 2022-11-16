package heuristics

import "strings"

func CalculatePointsStringDOTNET(extractedStrings []string) {

	// Tutti gli import dei binari .NET
	NetImports := map[string]int{
		"Systems.diagnostic":      2,
		"GetProcessesByName":      10,
		"get_SpecialDirectories":  20,
		"get_FileSystem":          2,
		"SpecialDirectoriesProxy": 10,
		"setShowInTaskBar":        20,
	}

	cryptoImports := map[string]int{
		"AESEncryptFile":               40,
		"AESDecryptFile":               40,
		"AESEncryptBytes":              20,
		"AESDecryptBytes":              20,
		"CryptoStream":                 20,
		"SymmetricAlgorithm":           20,
		"CreateEncryptor":              20,
		"System.Security.Cryptography": 30,
		"RijndaelManaged":              30,
		"set_KeySize":                  30,
		"set_BlockSize":                30,
		"get_KeySize":                  30,
		"set_IV":                       30,
		"CipherMode":                   30,
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range NetImports {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa "+extractedStrings[i]+" indica una funzione strettamente correlata ad un ransomware codificato in .NET.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range cryptoImports {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica una funzione della Crypto API di DotNet.", pointsToAdd)
			}
		}

		if strings.Contains(extractedStrings[i], "Confuser.Core") {
			InsertAnomalyString("La stringa\""+"\" indica che molto probabilmente il programma è stato offuscato con Confuser.Core", 30)
		}

	}

	//AESEncryptFile, AESDecryptFile, AESEncryptBytes,AESDecryptBytes,CheckPassword,GenerateKey 20 per ognuno tranne gli ultimi due
	// System.Security.Cryptography,AesCryptoServiceProvider
}
