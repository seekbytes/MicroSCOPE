package heuristics

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func CalculatePointsStringGO(extractedStrings []string) {
	/*
		strings := map[string]int{
			"CryptBlocks": 10,
		}*/

}

func CalculateStrings(extractedStrings []string) {

	// Stringhe proprie dei ransomware
	// Le seguenti stringhe sono state estratte da ransomware già studiati (in particolari dai file di riscatto)
	ransomware := map[string]int{
		"Your files has been":                         50,
		"Your files are encrypted":                    50,
		"we offer you to decrypt two random files":    100,
		"you should download and install TOR browser": 100,
		"All of your files are currently encrypted":   100,
		"DON'T TRY TO RECOVER":                        100,
		".onion":                                      50,
		"damage the cipher":                           20,
		"decryption will be impossible":               20,
		"Can I recover my files?":                     50,
		"encrypt all":                                 40,
	}

	// packers
	packers := map[string]int{
		"UPX\\!": 10,
		"UPX0":   10,
	}

	extensions := map[string]int{
		".pvp":      1,
		".avhd":     1,
		".vhd":      1,
		".html":     1,
		".docx":     1,
		".pdf":      1,
		".txt":      1,
		".key":      1,
		".sqlite":   1,
		".backup":   1,
		".vbs":      1,
		".cfg":      1,
		".svn-base": 1,
		".asm":      1,
		".psd":      1,
		".lua":      1,
		".vcproj":   1,
		".psd1":     1,
	}

	openssl := map[string]int{
		"assertion failed: bl <= (int)sizeof(ctx->buf)\n": 10,
		"crypto\\bio\\bss_mem.c\n":                        10,
		"crypto\\pem\\pem_lib.c\n":                        10,
		"OpenSSL PKCS#1 RSA (from Eric Young)\n":          10,
		"CRYPTOGAMS by <appro@openssl.org>":               10,
	}

	pointsSSL := 0

	for i := 0; i < len(extractedStrings); i++ {
		pointsExtensions := 0
		for stringToCompare, pointsToAdd := range extensions {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				pointsExtensions += pointsToAdd
			}
		}
		if pointsExtensions > 4 {
			addExtensionList(extractedStrings[i])
		}

		for stringToCompare, pointsToAdd := range ransomware {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma è molto simile ad un ransomware.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range packers {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma è molto probabilmente stato compresso con UPX o similari.", pointsToAdd)
			}
		}

		// Controlla se è un indirizzo Bitcoin
		if len(extractedStrings) > 26 && len(extractedStrings) < 35 {
			if extractedStrings[i][0] == '1' || extractedStrings[i][0:3] == "bc1" || extractedStrings[i][0] == '3' {
				InsertAnomaly("La stringa "+extractedStrings[i]+" potrebbe indicare un indirizzo Bitcoin", 5)
			}
		}

		// Controlla se è un indirizzo di Monero
		if len(extractedStrings) == 94 {
			if extractedStrings[i][0] == '4' {
				InsertAnomaly("La stringa "+extractedStrings[i]+" potrebbe indicare un indirizzo Monero", 5)

			}
		}

		// Identifica se viene utilizzato OpenSSL
		for stringToCompare, pointsToAdd := range openssl {
			if pointsSSL < 10 && strings.Contains(extractedStrings[i], stringToCompare) {
				pointsSSL += pointsToAdd
				InsertAnomaly("Questo binario utilizza la libreria OpenSSL.", 5)
				break
			}
		}
	}

}

func addExtensionList(s string) {
	InsertAnomaly("Questo binario controlla una certa lista di estensioni che non hanno alcun elemento in comune: "+s, 30)
}

func CalculatePointsStringELF(extractedStrings []string) {

	pathToIgnore := map[string]int{
		"/usr/lib32":  5,
		"/lost+found": 20,
	}

	ransomware := map[string]int{
		"/dev/urandom":           10, // ransomware ottiene entropia dall'ambiente
		"Locked":                 5,
		"Lock":                   5,
		"Usage example":          2,   // utilizziamo questa stringa per ricavare un possibile descrizione dall'"help" del programma
		"esxcli vm process kill": 100, // a meno che non sia VMWARE, non c'è motivo di accedere esxcli e di uccidere tutti i processi
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range pathToIgnore {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica eventuali percorsi che il programma potrebbe ignorare.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range ransomware {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" è simile ad altre stringhe individuate su ransomware.", pointsToAdd)
			}
		}
	}
}

func CalculatePointsStringPE(extractedStrings []string, isDotNet bool) int {
	/* WINDOWS */
	points := 0

	// Stringhe che evidenziano eventuali azioni di distruzione file/cartelle
	deleteStrings := map[string]int{
		"vssadmin Delete": 10, // deleteShadowcopies
		"vssadmin":        10, // modifica
		"del /s /f":       10,
	}

	ignoredPath := map[string]int{
		"\\Windows\\":                   1,
		"\\System Volume Information\\": 1,
		"\\$RECYCLE.BIN\\":              1,
		"\\WINNT":                       1,
		"\\ProgramData\\":               1,
		"$\\Windows.old\\":              1,
		"\\Microsoft\\Windows\\":        1,
		"\\Google\\Chrome\\":            1,
		"\\AppData":                     1,
		"\\ntuser.ini":                  1,
		"\\bootmgr":                     1,
		"\\autorun.inf":                 1,
		"\\boot.ini":                    1,
	}

	processes := map[string]int{
		"msftesql":             1,
		"sqlagent.exe":         1,
		"sqlbrowser.exe":       1,
		"synctime.exe":         1,
		"agntsvc.exe":          1,
		"isqlplussvc.exe":      1,
		"xfssvccon.exe":        1,
		"encsvc.exe":           1,
		"ocautoupds.exe":       1,
		"mydesktopservice.exe": 1,
		"firefoxconfig.exe":    1,
		"tbirdconfig.exe":      1,
		"mydesktopqos.exe":     1,
		"ocomm.exe":            1,
		"mysqld.exe":           1,
		"mysqld-nt.exe":        1,
		"mysqld-opt.exe":       1,
		"dbeng50.exe":          1,
		"sqbcoreservice.exe":   1,
		"excel.exe":            1,
		"infopath.exe":         1,
		"msaccess.exe":         1,
		"mspub.exe":            1,
		"onenote.exe":          1,
		"outlook.exe":          1,
		"powerpnt.exe":         1,
		"sqlservr.exe":         1,
		"thebat.exe":           1,
		"steam.exe":            1,
		"thebat64.exe":         1,
		"thunderbird.exe":      1,
		"visio.exe":            1,
		"winword.exe":          1,
		"wordpad.exe":          1,
		"QBW32.exe":            1,
		"QBW64.exe":            1,
		"ipython.exe":          1,
		"python.exe":           1,
		"dumpcap.exe":          1,
		"procmon.exe":          1,
		"procmon64.exe":        1,
		"procexp.exe":          1,
		"procexp64.exe":        1,
	}

	// Tutti gli import dei binari .NET
	NetImports := map[string]int{
		"Systems.diagnostic":      2,
		"GetProcessesByName":      10,
		"get_SpecialDirectories":  20,
		"get_FileSystem":          2,
		"SpecialDirectoriesProxy": 10,
		"setShowInTaskBar":        20,
	}

	for i := 0; i < len(extractedStrings); i++ {

		for stringToCompare, pointsToAdd := range deleteStrings {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma elimina copie shadow o copie di backup.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range ignoredPath {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma ignora alcune path di sistema.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range processes {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma utilizza attivamente il processo.", pointsToAdd)
			}
		}

		if isDotNet {
			for stringToCompare, pointsToAdd := range NetImports {
				if strings.Contains(extractedStrings[i], stringToCompare) {
					InsertAnomaly("La stringa "+extractedStrings[i]+" indica che il programma utilizza funzioni che reperiscono informazioni.", pointsToAdd)
				}
			}
		}

		if strings.Contains(extractedStrings[i], "Wallpaper /T REG_SZ /F /D") {
			InsertAnomaly("Il programma cambia wallpaper da linea di comando. Questo metodo è spesso utilizzato da programmi malevoli.", 10)
		}

		// TODO: FixME!
		var strToDecode string
		strToDecode = extractedStrings[i]
		for {
			if strToDecode[len(strToDecode)-1] == '=' && len(strToDecode)%4 == 0 {
				tmp, err := base64.StdEncoding.DecodeString(strToDecode)
				if err != nil {
					break
				}
				strToDecode = string(tmp)
			} else {
				break
			}
		}

		if strToDecode != extractedStrings[i] {
			fmt.Println(strToDecode)
			InsertAnomaly("Individuata stringa Base64. "+extractedStrings[i], 3)
		}

	}

	return points
}
