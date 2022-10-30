package heuristics

import (
	"microscope/formats/pe"
)

func CalculatePointsImports(Imports []*pe.ImportInfo) {
	// https://malapi.io/

	// API per acquisire informazioni
	gatheringImports := map[string]int{
		"GetProcessList": 10,
		"Process32First": 10,
		"GetStartupInfo": 10,
	}

	antiDebuggingImports := map[string]int{
		"IsDebuggerPresent":              5,
		"GetSystemInfo":                  5,
		"GetLogicalProcessorInformation": 10,
		"IsProcessorFeaturePresent":      10,
		"CreateToolhelp32Snapshot":       20,
		"GetUserDefaultLangID":           2,
		"TerminateProcess":               10,
		"NtYieldExecution":               20,
	}

	queueIOImports := map[string]int{
		"DeviceIoControl":            10,
		"CreateIOCompletionPort":     5,
		"PostQueuedCompletionStatus": 5,
		"SetProcessPriorityBoost":    10, // Aumenta la priorità di un thread
	}

	stealthImports := map[string]int{
		"VirtualProtect":          5,
		"ReadProcessMemory":       4,
		"NtWriteVirtualMemory":    5,
		"CreateRemoteThread":      5,
		"RtlAddAccessDeniedAce":   10,
		"NtSetInformationProcess": 5,
		"ShellExecute":            10,
	}

	networkImports := map[string]int{
		"WNetOpenEnum":      5,
		"WNetEnumResource":  5,
		"WNetCloseEnum":     5,
		"WNetAddConnection": 5,
	}

	fileImports := map[string]int{
		"FindFirstVolume":          10,
		"FindNextVolume":           10,
		"GetLogicalDrives":         10,
		"GetFileType":              20,
		"GetCompressed":            20,
		"FindFirstFile":            20,
		"SetRenameInformationFile": 10,
	}

	ransomwareImports := map[string]int{
		"CryptDeriveKey":           10,
		"CryptEncrypt":             10,
		"CryptDecrypt":             10,
		"CryptImportPublicKeyInfo": 20,
		"CryptAcquireContext":      20,
		"CryptDestroyKey":          20,
		"CryptRelaseContext":       20,
		"CryptStringToBinary":      20,
		"CryptBinaryToString":      20,
		"CryptGenKey":              20,
		"FindNextFile":             10, // https://core.ac.uk/download/pdf/159235636.pdf
		"SystemFunction036":        10, // funzione per generare un numero casuale, non abitualmente utilizzata (vedi RtlGenRandom)
	}

	securityImports := map[string]int{
		"GetSecurityDescriptorSacl":    5,
		"GetSecurityDescriptorDacl":    5,
		"GetSecurityDescriptorGroup":   5,
		"GetSecurityDescriptorOwner":   5,
		"GetSecurityDescriptorControl": 5,
	}

	for i := 0; i < len(Imports); i++ {
		// Controlla ogni import

		importName := Imports[i].APICalled
		// Rimuove dagli import le ultime lettere W (Unicode) e A (Ascii)
		if len(importName) >= 3 {

			if importName[len(importName)-1] == 'W' || importName[len(importName)-1] == 'A' {
				importName = importName[:len(importName)-1]
			}

			if importName[(len(importName)-3):(len(importName)-1)] == "Ex" {
				importName = importName[:len(importName)-3]
			}
		}

		// API per l'anti-debugging
		if pointToAdd, isFound := antiDebuggingImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che presenta caratteristiche anti-debugging: "+importName, pointToAdd)
		}

		// API che reperiscono informazioni senza che l'utente se ne accorga
		if pointToAdd, isFound := stealthImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che reperisce informazioni sul sistema: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := ransomwareImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione compatibile con il comportamento di un ransomware: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := queueIOImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che modifica la coda dei dispositivi I/O: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := networkImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che utilizza la rete: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := gatheringImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che acquisisce informazioni sui processi in uso o sull'environment: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := securityImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che acquisisce informazioni sul contesto di sicurezza per l'utente: \""+importName+"\"", pointToAdd)
		}

		if pointToAdd, isFound := fileImports[importName]; isFound {
			InsertAnomalyImports("È stata trovata una funzione che acquisisce informazioni sui dispositivi di memoria secondaria: \""+importName+"\"", pointToAdd)
		}

	}

}
