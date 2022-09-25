package heuristics

import (
	"fmt"
	"microscope/formats/pe"
)

func CalculatePointsImports(Imports []*pe.ImportInfo) int {
	points := 0

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

	/*miscActions := map[string]int{
		"LoadLibrary": 2, // non possiamo essere così restrittivi dato che anche un normale programma carica una libreria
	}*/

	networkImports := map[string]int{
		"WNetOpenEnum":      5,
		"WNetEnumResource":  5,
		"WNetCloseEnum":     5,
		"WNetAddConnection": 5,
	}

	ransomwareImports := map[string]int{
		"CryptDeriveKey":           10,
		"CryptEncrypt":             10,
		"CryptDecrypt":             4,
		"CryptImportPublicKeyInfo": 10,
		"CryptAcquireContext":      10,
		"CryptGenKey":              10,
		"GetFileType":              10,
		"FindFirstFile":            20,
		"SetRenameInformationFile": 10,
		"FindNextFile":             10, // https://core.ac.uk/download/pdf/159235636.pdf
		"SystemFunction036":        10, // funzione per generare un numero casuale, non abitualmente utilizzata (vedi RtlGenRandom)
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
			InsertAnomaly("È stata trovata una funzione che presenta caratteristiche anti-debugging: "+importName, pointToAdd)
		}

		// API che reperiscono informazioni senza che l'utente se ne accorga
		if pointToAdd, isFound := stealthImports[importName]; isFound {
			InsertAnomaly("È stata trovata una funzione che reperisce informazioni sul sistema: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := ransomwareImports[importName]; isFound {
			InsertAnomaly("È stata trovata una funzione compatibile con il comportamento di un ransomware: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := queueIOImports[importName]; isFound {
			InsertAnomaly("È stata trovata una funzione che modifica la coda dei dispositivi I/O: "+importName, pointToAdd)
		}

		if pointToAdd, isFound := networkImports[importName]; isFound {
			fmt.Printf("%s : %d \n", importName, pointToAdd)
			points += pointToAdd
		}

		if pointToAdd, isFound := gatheringImports[importName]; isFound {
			InsertAnomaly("È stata trovata una funzione che acquisisce informazioni sui processi in uso o sull'environment: "+importName, pointToAdd)
		}

	}

	return points
}
