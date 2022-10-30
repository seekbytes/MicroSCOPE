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
		"AESEncryptFile":          10,
		"AESDecryptFile":          10,
		"AESEncryptBytes":         10,
		"AESDecryptBytes":         10,
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range NetImports {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa "+extractedStrings[i]+" indica una funzione strettamente correlata ad un ransomware codificato in .NET.", pointsToAdd)
			}
		}
	}

	//AESEncryptFile, AESDecryptFile, AESEncryptBytes,AESDecryptBytes,CheckPassword,GenerateKey 20 per ognuno tranne gli ultimi due
	// System.Security.Cryptography,AesCryptoServiceProvider
}
