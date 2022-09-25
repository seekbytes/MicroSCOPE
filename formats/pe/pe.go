package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"microscope/utils"
)

var fileAnalyzed *PEBINARY
var reader *bytes.Reader

func Analysis(PEStruct *PEBINARY, content []byte) {
	fileAnalyzed = PEStruct
	reader = bytes.NewReader(content)

	var DosHeader DosHeaderT

	// Il formato file PE utilizza solamente little endian
	// Fonte: https://reverseengineering.stackexchange.com/questions/17922/determining-endianness-of-pe-files-windows-on-arm
	err := binary.Read(reader, binary.LittleEndian, &DosHeader)

	if err != nil {
		fmt.Println("Impossibile leggere la sezione DosHeader " + err.Error())
		return
	}

	if DosHeader.MagicDos != MAGIC_MSDOS {
		fmt.Println("Il file non è un eseguibile per MS-DOS.")
		return
	}

	fileAnalyzed.DosHeader = &DosHeader

	// Controlliamo la signature per i PE
	var PESignature uint32

	// Sposta l'offset all'inizio dell'intestazione del file PE
	_, err = reader.Seek(int64(DosHeader.AddressExeOffset), io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile spostare l'offset del PE per il seguente motivo " + err.Error())
		return
	}

	err = binary.Read(reader, binary.LittleEndian, &PESignature)
	if err != nil {
		fmt.Println("Impossibile leggere la signature del PE per il seguente motivo " + err.Error())
		return
	}

	// Confrontiamo la PE Signature con la stringa "EP" (al contrario perché siamo su Little Endian)
	if PESignature != MAGIC_PE {
		fmt.Println("Il file in input non è un binario compatibile PE o PE+. Molto probabilmente è MS-DOS.")
		return
	}

	// Impostiamo il seek per analizzare il COFFHeader (posizionato all'offset addressExeOffset + 4 byte di PEsignature)
	var CoffHeader COFFHeaderT

	_, err = reader.Seek(int64(DosHeader.AddressExeOffset+4), io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile impostare l'offset durante la lettura del CoffHeader per il seguente motivo: " + err.Error())
		return
	}

	err = binary.Read(reader, binary.LittleEndian, &CoffHeader)
	if err != nil {
		fmt.Println("Errore nella lettura del CoffHeader : " + err.Error())
		return
	}
	fileAnalyzed.COFFHeader = CoffHeader

	// Saltiamo il COFFHeader
	_, err = reader.Seek(int64(DosHeader.AddressExeOffset+4)+int64(binary.Size(COFFHeaderT{})), io.SeekStart)

	// Leggiamo la MagicPESignature, due byte che vengono utilizzati per capire se è un binario PE
	// (indirizzamento 32 bit) oppure PE+ (indirizzamento 64 bit)
	var MagicPESignature uint16
	err = binary.Read(reader, binary.LittleEndian, &MagicPESignature)
	if err != nil {
		fmt.Println("Errore nella lettura del magicPESignature.")
		return
	}

	is64bit := false

	if MagicPESignature == MAGIC_PE_32BIT {
		is64bit = false
	} else if MagicPESignature == MAGIC_PE_64BIT {
		is64bit = true
		fileAnalyzed.Is64bit = true
	} else {
		fmt.Println("Numero magic invalido. Non è un file PE")
		return
	}

	var NumberOfRvaAndSizes int64

	// Lettura dell'optional header, dobbiamo distinguere l'optional header per 64 bit da quello da 32 bit
	// (vedi pe_structs.go per il motivo)
	if is64bit {
		var optionalHeader PEPOptionalHeaderT
		err = binary.Read(reader, binary.LittleEndian, &optionalHeader)
		if err != nil {
			fmt.Println("Impossibile leggere l'optionalHeader" + err.Error())
			return
		}
		NumberOfRvaAndSizes = int64(optionalHeader.NumberOfRvaAndSizes)
		fileAnalyzed.OptionalHeader = optionalHeader
	} else {
		var optionalHeader PEOptionalHeaderT
		err = binary.Read(reader, binary.LittleEndian, &optionalHeader)
		if err != nil {
			fmt.Println("Impossibile leggere l'optionalHeader.")
			return
		}
		NumberOfRvaAndSizes = int64(optionalHeader.NumberOfRvaAndSizes)
		fileAnalyzed.OptionalHeader = optionalHeader
	}

	// Recupera le diverse sezioni del file binario
	var dimensionsOptionalHeader int64
	if is64bit {
		dimensionsOptionalHeader = int64(binary.Size(PEPOptionalHeaderT{}))
	} else {
		dimensionsOptionalHeader = int64(binary.Size(PEOptionalHeaderT{}))
	}

	var DataDirectories [16]ImageDataDirectory

	for i := 0; i < int(NumberOfRvaAndSizes); i++ {
		var RVATemp ImageDataDirectory
		err = binary.Read(reader, binary.LittleEndian, &RVATemp)
		if err != nil {
			fmt.Println("Impossibile leggere l'ImageDataDirectory per il seguente motivo: " + err.Error())
		}
		DataDirectories[i] = RVATemp
	}

	fileAnalyzed.DataDirectories = DataDirectories

	// L'inizio delle sezioni è: puntatore dell'intestazione per il binario + 4 (signature) + COFFHeaderT + 2 di magic +
	// + OptionalHeader + le imageDataDirectory * NumberOfRVAAndSizes
	sectionStart := int64(DosHeader.AddressExeOffset) + 4 + int64(binary.Size(COFFHeaderT{})) + 2 + dimensionsOptionalHeader + 8*NumberOfRvaAndSizes
	_, err = reader.Seek(sectionStart, io.SeekStart)

	var Sections []*Section
	var SectionsHeader []*SectionHeader
	Sections = make([]*Section, int(CoffHeader.NumberOfSections))
	SectionsHeader = make([]*SectionHeader, int(CoffHeader.NumberOfSections))

	for i := 0; i < int(CoffHeader.NumberOfSections); i++ {

		// Scorri le varie sezioni
		_, err = reader.Seek(sectionStart+int64(binary.Size(SectionHeader{})*i), io.SeekStart)

		if err != nil {
			fmt.Println("Errore durante il seek per il seguente motivo " + err.Error())
			return
		}

		// Crea un nuovo "oggetto" di tipo SectionHeader
		var tmp SectionHeader

		err = binary.Read(reader, binary.LittleEndian, &tmp)
		if err != nil {
			fmt.Println("Impossibile leggere la sezione per il seguente motivo " + err.Error())
			return
		}

		Sections[i] = &Section{
			Name:                 utils.ReadString(tmp.Name[:8]), // limita il nome a OTTO caratteri (nomi più grandi sono validi SOLO per librerie DLL)
			VirtualSize:          tmp.VirtualSize,
			VirtualAddress:       tmp.VirtualAddress,
			SizeOfRawData:        tmp.SizeOfRawData,
			PointerToRawData:     tmp.PointerToRawData,
			PointerToRelocations: tmp.PointerToRelocations,
			PointerToLineNumbers: tmp.PointerToLineNumbers,
			NumberOfRelocations:  tmp.NumberOfRelocations,
			NumberOfLineNumbers:  tmp.NumberOfLineNumbers,
			Characteristics:      tmp.Characteristics,
		}
		SectionsHeader[i] = &tmp

		// Lettura del raw data
		_, err = reader.Seek(int64(tmp.PointerToRawData), io.SeekStart)
		if err != nil {
			fmt.Println("Errore nell'impostazione dell'offset per il seguente motivo " + err.Error())
			return
		}

		raw := make([]byte, tmp.SizeOfRawData)
		_, err = reader.Read(raw)

		if err != nil {
			// Se siamo arrivati in fondo al contenuto, procediamo
			if err == io.EOF {
				Sections[i].Raw = nil
				continue
			}
			fmt.Println("Impossibile leggere la sezione per il seguente motivo " + err.Error())
		}

		Sections[i].Raw = raw
		// Calcolo entropia
		Sections[i].Entropy = utils.CalculateEntropy(raw)
	}

	fileAnalyzed.Sections = Sections
	// Memorizziamo l'intero header come sezione
	RawHeaders := content[0:sectionStart]
	fileAnalyzed.Header = &Section{
		"HeaderSection",
		utils.CalculateEntropy(RawHeaders),
		uint32(len(RawHeaders)),
		0,
		uint32(len(RawHeaders)),
		0,
		0,
		0,
		0, 0,
		0,
		RawHeaders,
	}

	// Se, all'interno del binario, la dimensione della sezione per l'export è diverso 0, procediamo con la lettura degli export
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0 {
		readExports(DataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	}

	// Sezione Import
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0 {
		readImports(is64bit, DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	}

	// Sezione Risorse
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0 {
		readResourceDirectory(DataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)

		// ricavo l'offset rsrc
		section := getSectionFromVirtualAddress(uint64(DataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress))

		// per ogni risorsa trovata vado a fare il seek e leggere n byte da scrivere su un file esterno
		for i := 0; i < len(fileAnalyzed.Resource); i++ {
			offset := int64(fileAnalyzed.Resource[i].Offset) - int64(DataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + int64(section.PointerToRawData)
			_, err = reader.Seek(offset, io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile spostare il seek.")
				return
			}
			contenuto := make([]byte, fileAnalyzed.Resource[i].Size)
			err = binary.Read(reader, binary.LittleEndian, &contenuto)
			fileAnalyzed.Resource[i].Content = contenuto
			fileAnalyzed.Resource[i].ContentType = utils.IdentifyFile(contenuto)
			if fileAnalyzed.Resource[i].Name == "" {
				fileAnalyzed.Resource[i].Name = PrintResource(fileAnalyzed.Resource[i].Type)
			}

			// Parsa i diversi tipi di risorsa

			if fileAnalyzed.Resource[i].Type == 16 {
				// versionInfo
				// https://docs.microsoft.com/it-it/windows/win32/menurc/vs-versioninfo
				fileAnalyzed.Resource[i].ContentType = "pe/VersionInfo"
				parseVersionInfo(fileAnalyzed.Resource[i].Content)
			}

			if fileAnalyzed.Resource[i].Type == 24 {
				fileAnalyzed.Resource[i].ContentType = "text/xml"
			}

		}

	}

	// Sezione exceptions
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size != 0 {
	}

	// Sezione security
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0 {
		readSecuritySection(DataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress)
	}

	// Sezione basereloc
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0 {

	}

	// Sezione debug
	if DataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size != 0 {
		readDebugSection(DataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)
		readDebugInformations()
	}

	// Sezione APISET
	readApiSet()

	// RichHeader
	readRichHeader()

	// estrazione stringhe
	ReadSymbolTable()
}

type FixedVersionInfo struct {
	Signature        uint32
	StructVersion    uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubType      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type VersionInfo struct {
	Length      uint16   // Lunghezza della struttura VS_VERSIONINFO
	ValueLength uint16   // Lunghezza del membro Value
	Type        uint16   // Tipo di dati nella risorsa della versione (1 se contiene dati di testo, 0 se binari)
	SzKey       [32]byte // Stringa "VS_VERSION_INFO" (16 * 2)
	Padding1    uint16
	Value       FixedVersionInfo
	Padding2    uint16
	Children    uint16
}

func parseVersionInfo(contenuto []byte) {

	var version VersionInfo
	reader := bytes.NewReader(contenuto)
	err := binary.Read(reader, binary.LittleEndian, &version)

	if err != nil {
		fmt.Println("Impossibile leggere il contenuto di versioninfo")
		return
	}
}

func getSectionFromVirtualAddress(VirtualAddress uint64) *Section {
	// Da VirtualAddress, la funzione restituisce il puntatore alla sezione in cui VirtualAddress è contenuto

	var section *Section

	if VirtualAddress > 0 && VirtualAddress < uint64(fileAnalyzed.Header.VirtualSize) {
		return fileAnalyzed.Header
	}

	for i := 0; i < int(fileAnalyzed.COFFHeader.NumberOfSections); i++ {
		if VirtualAddress >= uint64(fileAnalyzed.Sections[i].VirtualAddress) && VirtualAddress < uint64(fileAnalyzed.Sections[i].VirtualAddress+fileAnalyzed.Sections[i].SizeOfRawData) {
			section = fileAnalyzed.Sections[i]
		}
	}

	return section
}
