package heuristics

import (
	"encoding/base64"
	"fmt"
	"microscope/utils"
	"regexp"
	"strconv"
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
		"All of your files are encrypted":             100,
		"DON'T TRY TO RECOVER":                        100,
		"All encrypted files":                         100,
		"damage the cipher":                           20,
		"decryption will be impossible":               20,
		"Can I recover my files?":                     50,
		"encrypt all":                                 40,
	}

	// packers
	packers := map[string]int{
		"UPX\\!":                   10,
		"UPX0":                     10,
		"CounfuserEx":              20,
		"Powered by SmartAssembly": 20,
	}

	// Lista di estensioni
	extensions := map[string]int{
		"pvp":      1,
		"avhd":     1,
		"vhd":      1,
		"html":     1,
		"docx":     1,
		"pdf":      1,
		"txt":      1,
		"key":      1,
		"sqlite":   1,
		"backup":   1,
		"vbs":      1,
		"cfg":      1,
		"svn-base": 1,
		"asm":      1,
		"psd":      1,
		"lua":      1,
		"vcproj":   1,
		"psd1":     1,
		"raw":      1,
		"7z":       1,
		"db3":      1,
		"keystore": 1,
	}

	openssl := map[string]int{
		"assertion failed: bl <= (int)sizeof(ctx->buf)": 10,
		"crypto\\bio\\bss_mem.c":                        10,
		"crypto\\pem\\pem_lib.c":                        10,
		"OpenSSL PKCS#1 RSA (from Eric Young)":          10,
		"CRYPTOGAMS by <appro@openssl.org>":             10,
	}

	pointsSSL := 0
	var librerieTrovate []string

	for i := 0; i < len(extractedStrings); i++ {
		pointsExtensions := 0
		for stringToCompare, pointsToAdd := range extensions {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				pointsExtensions += pointsToAdd
			}
		}
		if pointsExtensions > 6 {
			addExtensionList(extractedStrings[i])
		}

		for stringToCompare, pointsToAdd := range ransomware {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica che il programma è molto simile ad un ransomware.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range packers {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica che il programma è molto probabilmente stato compresso con UPX o similari.", pointsToAdd)
			}
		}

		if strings.Contains(extractedStrings[i], ".onion") {
			if !strings.Contains(extractedStrings[i], "<") {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" è un indirizzo Tor.", 40)
			}
		}

		// Estrazione Bitcoin Address alternativa

		isBitcoin, _ := regexp.Match("^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", []byte(extractedStrings[i]))
		if isBitcoin {
			// La RegEX identifica anche numeri!
			if _, err := strconv.Atoi(extractedStrings[i]); err == nil {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica un indirizzo Bitcoin", 10)
			}
		}

		// Controlla se è un indirizzo di Monero
		if len(extractedStrings) == 95 {
			if extractedStrings[i][0] == '4' || extractedStrings[i][0] == '8' {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" potrebbe indicare un indirizzo Monero", 5)
			}
		}

		// Identifica se viene utilizzato OpenSSL
		for stringToCompare, pointsToAdd := range openssl {
			if pointsSSL < 10 && strings.Contains(extractedStrings[i], stringToCompare) {
				pointsSSL += pointsToAdd
				InsertAnomalyString("Questo binario utilizza la libreria OpenSSL.", 5)
				break
			}
		}

		// Identifica altre librerie utilizzate
		wasFound := strings.Index(extractedStrings[i], "CRYPTOGAMS by <appro@openssl.org>")
		if wasFound != -1 {
			librerieTrovate = append(librerieTrovate, extractedStrings[i][0:wasFound])
		}

		// Identifica stringhe Base64
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
			if utils.IsASCIIPrintable(strToDecode) {
				InsertAnomalyString("Individuata stringa Base64. "+extractedStrings[i], 3)
			}
		}

	}

	if len(librerieTrovate) != 0 {
		libString := fmt.Sprintf("%v", librerieTrovate)
		InsertAnomalyString("Sono state individuate le seguenti librerie che implementano algoritmi per la crittografia:\n "+libString, 20*len(librerieTrovate))
	}

}

func addExtensionList(s string) {
	InsertAnomalyString("Questo binario controlla una certa lista di estensioni che non hanno alcun elemento in comune: "+s, 30)
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
		"esxcli vm process kill": 100, // a meno che non sia VMWARE, non c'è motivo di accedere esxcli e di uccidere tutti i processi
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range pathToIgnore {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica eventuali percorsi che il programma potrebbe ignorare.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range ransomware {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" è simile ad altre stringhe individuate su ransomware.", pointsToAdd)
			}
		}

		if strings.Contains(extractedStrings[i], "Usage example") {
			// utilizziamo questa stringa per ricavare un possibile descrizione dall'"help" del programma
			InsertAnomalyString("È stata rilevata una descrizione di un help del programma: "+extractedStrings[i], 0)
		}

	}
}

func transformUUIDToFolder(uuid string) string {

	uuidToFolderMap := map[string]string{
		"DE61D971-5EBC-4F02-A3A9-6C82895E5C04": "AddNewPrograms",
		"724EF170-A42D-4FEF-9F26-B60E846FBA4F": "AdminTools",
		"A520A1A4-1780-4FF6-BD18-167343C5AF16": "AppDataLow",
		"A305CE99-F527-492B-8B1A-7E76FA98D6E4": "AppUpdates",
		"9E52AB10-F80D-49DF-ACB8-4330F5687855": "CDBurning",
		"DF7266AC-9274-4867-8D55-3BD661DE872D": "ChangeRemovePrograms",
		"D0384E7D-BAC3-4797-8F14-CBA229B392B5": "CommonAdminTools",
		"C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D": "CommonOEMLinks",
		"0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8": "CommonPrograms",
		"A4115719-D62E-491D-AA7C-E74B8BE3B067": "CommonStartMenu",
		"82A5EA35-D9CD-47C5-9629-E15D2F714E6E": "CommonStartup",
		"B94237E7-57AC-4347-9151-B08C6C32D1F7": "CommonTemplates",
		"0AC0837C-BBF8-452A-850D-79D08E667CA7": "Computer",
		"4BFEFB45-347D-4006-A5BE-AC0CB0567192": "Conflict",
		"6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD": "Connections",
		"56784854-C6CB-462B-8169-88E350ACB882": "Contacts",
		"82A74AEB-AEB4-465C-A014-D097EE346D63": "ControlPanel",
		"2B0F765D-C0E9-4171-908E-08A611B84FF6": "Cookies",
		"B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
		"FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
		"374DE290-123F-4565-9164-39C4925E467B": "Downloads",
		"1777F761-68AD-4D8A-87BD-30B759FA33DD": "Favorites",
		"FD228CB7-AE11-4AE3-864C-16F3910AB8FE": "Fonts",
		"CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434": "Games",
		"054FAE61-4DD8-4787-80B6-090220C4B700": "GameTasks",
		"D9DC8A3B-B784-432E-A781-5A1130A75963": "History",
		"4D9F7874-4E0C-4904-967B-40B0D20C3E4B": "Internet",
		"352481E8-33BE-4251-BA85-6007CAEDCF9D": "InternetCache",
		"BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968": "Links",
		"F1B32785-6FBA-4FCF-9D55-7B8E7F157091": "LocalAppData",
		"2A00375E-224C-49DE-B8D1-440DF7EF3DDC": "LocalizedResourcesDir",
		"4BD8D571-6D19-48D3-BE97-422220080E43": "Music",
		"C5ABBF53-E17F-4121-8900-86626FC2C973": "NetHood",
		"D20BEEC4-5CA8-4905-AE3B-BF251EA09B53": "Network",
		"31C0DD25-9439-4F12-BF41-7FF4EDA38722": "Objects3D",
		"2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39": "OriginalImages",
		"69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C": "PhotoAlbums",
		"33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
		"DE92C1C7-837F-4F69-A3BB-86E631204A23": "Playlists",
		"76FC4E2D-D6AD-4519-A663-37BD56068185": "Printers",
		"9274BD8D-CFD1-41C3-B35E-B13F55A758F4": "PrintHood",
		"5E6C858F-0E22-4760-9AFE-EA3317B67173": "Profile",
		"62AB5D82-FDC1-4DC3-A9DD-070D1D495D97": "ProgramData",
		"905E63B6-C1BF-494E-B29C-65B732D3D21A": "ProgramFiles",
		"F7F1ED05-9F6D-47A2-AAAE-29D317C6F066": "ProgramFilesCommon",
		"6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D": "ProgramFilesCommonX64",
		"DE974D24-D9C6-4D3E-BF91-F4455120B917": "ProgramFilesCommonX86",
		"6D809377-6AF0-444B-8957-A3773F02200E": "ProgramFilesX64",
		"7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": "ProgramFilesX86",
		"A77F5D77-2E2B-44C3-A6A2-ABA601054A51": "Programs",
		"DFDF76A2-C82A-4D63-906A-5644AC457385": "Public",
		"C4AA340D-F20F-4863-AFEF-F87EF2E6BA25": "PublicDesktop",
		"ED4824AF-DCE4-45A8-81E2-FC7965083634": "PublicDocuments",
		"3D644C9B-1FB8-4F30-9B45-F670235F79C0": "PublicDownloads",
		"DEBF2536-E1A8-4C59-B6A2-414586476AEA": "PublicGameTasks",
		"3214FAB5-9757-4298-BB61-92A9DEAA44FF": "PublicMusic",
		"B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5": "PublicPictures",
		"2400183A-6185-49FB-A2D8-4A392A602BA3": "PublicVideos",
		"52A4F021-7B75-48A9-9F6B-4B87A210BC8F": "QuickLaunc",
		"AE50C081-EBD2-438A-8655-8A092E34987A": "Recent",
		"BD85E001-112E-431E-983B-7B15AC09FFF1": "RecordedTV",
		"B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC": "RecycleBin",
		"8AD10C31-2ADB-4296-A8F7-E4701232C972": "ResourceDir",
		"3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "RoamingAppData",
		"B250C668-F57D-4EE1-A63C-290EE7D1AA1F": "SampleMusic",
		"C4900540-2379-4C75-844B-64E6FAF8716B": "SamplePictures",
		"15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5": "SamplePlaylists",
		"859EAD94-2E85-48AD-A71A-0969CB56A6CD": "SampleVideos",
		"4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4": "SavedGames",
		"7D1D3A04-DEBB-4115-95CF-2F29DA2920DA": "SavedSearches",
		"EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E": "SEARCH_CSC",
		"98EC0E18-2098-4D44-8644-66979315A281": "SEARCH_MAPI",
		"190337D1-B8CA-4121-A639-6D472D16972A": "SearchHome",
		"8983036C-27C0-404B-8F08-102D10DCFD74": "SendTo",
		"7B396E54-9EC5-4300-BE0A-2482EBAE1A26": "SidebarDefaultParts",
		"A75D362E-50FC-4FB7-AC2C-A8BEAA314493": "SidebarParts",
		"625B53C3-AB48-4EC1-BA1F-A1EF4146FC19": "StartMenu",
		"B97D20BB-F46A-4C97-BA10-5E3608430854": "Startup",
		"43668BF8-C14E-49B2-97C9-747784D784B7": "SyncManager",
		"289A9A43-BE44-4057-A41B-587A76D7E7F9": "SyncResults",
		"0F214138-B1D3-4A90-BBA9-27CBC0C5389A": "SyncSetup",
		"1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": "System",
		"D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": "SystemX86",
		"A63293E8-664E-48DB-A079-DF759E0509F7": "Templates",
		"5B3749AD-B49F-49C1-83EB-15370FBD4882": "TreeProperties",
		"0762D272-C50A-4BB0-A382-697DCD729B80": "UserProfiles",
		"F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F": "UsersFiles",
		"18989B1D-99B5-455B-841C-AB7C74E4DDFC": "Videos",
		"F38BF404-1D43-42F2-9305-67DE0B28FC23": "Windows",
	}

	for k, v := range uuidToFolderMap {
		if strings.Contains(uuid, k) {
			return v
		}
	}

	return ""

}

func CalculatePointsStringPE(extractedStrings []string) {
	/* WINDOWS */

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

	var processiUsed []string

	for i := 0; i < len(extractedStrings); i++ {

		// è un probabile uuid?
		if strings.Contains(extractedStrings[i], "knownfolder:{") {
			result := transformUUIDToFolder(extractedStrings[i])

			if result != "" {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica che il programma utilizza la cartella "+result+".", 20)
			}

		}

		for stringToCompare, pointsToAdd := range deleteStrings {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica che il programma elimina copie shadow o copie di backup.", pointsToAdd)
			}
		}

		for stringToCompare, pointsToAdd := range ignoredPath {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				if !strings.Contains(extractedStrings[i], "HKEY_") && !strings.Contains(extractedStrings[i], "SOFTWARE") && !strings.Contains(extractedStrings[i], "Software") {
					InsertAnomalyString("La stringa \""+extractedStrings[i]+"\" indica che il programma utilizza alcune path di sistema.", pointsToAdd)
				}
			}
		}

		for stringToCompare, _ := range processes {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				processiUsed = append(processiUsed, stringToCompare)
			}
		}

		if strings.Contains(extractedStrings[i], "Wallpaper /T REG_SZ /F /D") {
			InsertAnomalyString("Il programma cambia wallpaper da linea di comando. Questo metodo è spesso utilizzato da programmi malevoli.", 10)
		}

	}

	if len(processiUsed) > 0 {
		processiUsedStr := fmt.Sprintf("%+#v ", processiUsed)
		InsertAnomalyString("Il programma utilizza attivamente i seguenti processi: "+processiUsedStr+".", 1*len(processiUsed))
	}

}
