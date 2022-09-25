package heuristics

import (
	"encoding/binary"
	"fmt"
	"microscope/formats/pe"
	"time"
)

func CheckHeaders() {

	var optionalHeader64 pe.PEPOptionalHeaderT

	optionalHeader32, ok := FileAnalyzed.PEInterface.OptionalHeader.(pe.PEOptionalHeaderT)
	if !ok {
		optionalHeader64, ok = FileAnalyzed.PEInterface.OptionalHeader.(pe.PEPOptionalHeaderT)
		if !ok {
			fmt.Println("Impossibile!")
			return
		}
	}

	dataDirectories := FileAnalyzed.PEInterface.DataDirectories

	var NumberOfRvaAndSizes int64
	var Checksum uint32
	if FileAnalyzed.PEInterface.Is64bit {
		NumberOfRvaAndSizes = int64(optionalHeader64.NumberOfRvaAndSizes)
		Checksum = optionalHeader64.Checksum
	} else {
		NumberOfRvaAndSizes = int64(optionalHeader32.NumberOfRvaAndSizes)
		Checksum = optionalHeader32.Checksum
	}

	CheckImageDataDirectories(dataDirectories, int(NumberOfRvaAndSizes))
	CheckOptionalHeader(optionalHeader64, FileAnalyzed.PEInterface.Is64bit)
	CheckCOFFHeader(&FileAnalyzed.PEInterface.COFFHeader)

	// Controllo checksum

	if Checksum != CalculateChecksum(FileAnalyzed.PEInterface.DosHeader.AddressExeOffset, uint32(len(FileAnalyzed.Raw)), FileAnalyzed.Raw) || Checksum == 0 {
		InsertAnomaly("Il checksum è diverso da quello calcolato.", 50)
	}
}

func CheckOptionalHeader(header pe.PEPOptionalHeaderT, is64bit bool) {
	if header.ImageBase%0x1000 != 0 {
		InsertAnomaly("Image base deve essere un multiplo di 4096.", 10)
	}

	if header.FileAlignment%2 != 0 {
		InsertAnomaly("FileAlignment deve essere una potenza di 2.", 10)
	}

	if header.FileAlignment < 512 {
		InsertAnomaly("FileAlignment deve essere un valore maggiore di 2.", 10)
	}

	if is64bit {
		if header.ImageBase+uint64(header.SizeOfImage) >= 0xffff080000000000 {
			InsertAnomaly("Anomalia: ImageBase overflow", 10)
		}
	} else {
		if header.ImageBase+uint64(header.SizeOfImage) >= 0x80000000 {
			InsertAnomaly("Anomalia: ImageBase overflow", 10)
		}
	}

	// Quando l'addressOfEntrypoint è minore della dimensione degli header, il file non può essere caricato in Windows 8
	if header.AddressOfEntryPoint != 0 && header.AddressOfEntryPoint < header.SizeOfHeaders {
		InsertAnomaly("AddressOfEntryPoint è minore della dimensione degli header, il file non può essere caricato in Windows 8.", 1)
	}

	// ImageBase può essere 0 in Windows NT 5
	// Da Windows NT 6, no
	if header.ImageBase == 0 {
		InsertAnomaly("Anomalia: ImageBase è zero.", 10)
	}

	// Win32VersionValue è un valore deprecato e deve essere impostato a ZERO
	// In alcune versioni di Windows, impostare questo campo con un valore diverso da zero può portare Windows a ignorare i campi sulle versioni
	// Attenzione a questo valore!!!
	if header.Win32VersionValue != 0 {
		InsertAnomaly("Attenzione: Win32Versionvalue non è zero. Impostare questo campo con un valore diverso da zero può portare il sistema operativo ad ignorare alcuni campi del binario.", 5)
	}

	if header.NumberOfRvaAndSizes < 0 || header.NumberOfRvaAndSizes > 16 {
		InsertAnomaly("ImageDataDirectory valore invalido.", 10)
	}

	if header.LoaderFlags != 0 {
		InsertAnomaly("Attenzione: LoaderFlags diverso da zero.", 10)
	}

	if header.AddressOfEntryPoint == 0 {
		InsertAnomaly("Attenzione: l'entrypoint è 0.", 10)
	}

	if int(header.SizeOfHeaders) < (binary.Size(pe.DosHeaderT{}) + binary.Size(pe.COFFHeaderT{})) {
		InsertAnomaly("Valore del SizeOfHeaders troppo basso.", 10)
	}

}

func CheckCOFFHeader(CoffHeader *pe.COFFHeaderT) {
	// Controlla il COFFHeader

	// Numero di sezioni è un intero positivo minore di 96
	if CoffHeader.NumberOfSections > 96 {
		InsertAnomaly("Attenzione: il numero di sezioni non può essere maggiore di 96.", 10)
	}

	// NumberOfSections può essere nullo (i valori in realtà sono controllati dal loader di Windows, ma non utilizzati)
	if CoffHeader.NumberOfSections == 0 {
		InsertAnomaly("Attenzione: il numero di sezioni non può essere minore di 1.", 10)
	}

	// Un programma di solito ha NOVE sezioni predefinite (.text, .bss, .rdata, .data, .rsrc, .edata, .idata, .pdata e .debug)
	// Windows NT 5 o precedenti: valore non può essere maggiore di 96
	// Windows NT 6: valore può raggiungere 65535
	if CoffHeader.NumberOfSections >= 10 {
		InsertAnomaly("Attenzione: il numero di sezioni è maggiore o uguale a 10", 10)
	}

	// La PointerToSymbolTable deve essere ZERO per gli eseguibili
	if CoffHeader.PointerToSymbolTable != 0 {
		InsertAnomaly("Attenzione: PointerToSymbolTable è diverso da zero.", 10)
	}

	if CoffHeader.TimeDateStamp == 0 {
		InsertAnomaly("Il timestamp è 0.", 10)
	}

	unixTime := time.Unix(int64(CoffHeader.TimeDateStamp), 0)
	fmt.Printf("Timestamp di compilazione: %v \n", unixTime)

	// Controlla se un timestamp è futuro
	if unixTime.After(time.Now()) {
		unixTimeStr := fmt.Sprintf("%v", unixTime)
		InsertAnomaly("Il timestamp del programma punta al futuro: "+unixTimeStr, 10)
	}

	// Se il timestamp punta al 20 Gennaio 2001, allora è probabile che il programma sia stato compilato con Delphi
	// Source: http://waleedassar.blogspot.com/2014/02/pe-timedatestamp-viewer.html
	if CoffHeader.TimeDateStamp == 0x2a425e19 {
		InsertAnomaly("Il programma è stato generato da un linker Delphi.", 0)
	}

	// SizeOfOptionalHeader è la differenza dal OptionalHeader e l'inizio delle tabelle delle sezioni
	if CoffHeader.SizeOfOptionalHeader == 0 {
		InsertAnomaly("SizeOfOptionalHeader è zero.", 10)
	}

	if CoffHeader.SizeOfOptionalHeader > uint16(binary.Size(pe.COFFHeaderT{})) {
		InsertAnomaly("La dimensione della SizeOfOptionalHeader è particolare.", 10)
	}

}

func CheckImageDataDirectories(DataDirectories [16]pe.ImageDataDirectory, NumberOfDataDirectory int) {
	// Funzione che controlla le sezioni disponibili

	// Controllo valori riservati
	if NumberOfDataDirectory == 16 && (DataDirectories[15].Size != 0 || DataDirectories[15].VirtualAddress != 0) {
		InsertAnomaly("Valori riservati della sezione Reserved devono essere posti a 0.", 10)
	}

	if NumberOfDataDirectory >= 8 && (DataDirectories[7].Size != 0 || DataDirectories[7].VirtualAddress != 0) {
		InsertAnomaly("Valori riservati della sezione Architecture devono essere posti a 0.", 10)
	}

}

func CalculateChecksum(offset uint32, size uint32, data []byte) uint32 {
	// Calcolo del checksum per il formato PE
	// Fonte: https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm

	var checksum uint64 = 0
	var max uint64 = 2 << 32

	currentDword := uint32(0)

	optionalHeaderOffset := offset + 4 + uint32(binary.Size(pe.COFFHeaderT{}))

	// Il campo checksum si trova alla posizione 64 dell'optionalHeader (sia per il caso PE che per il PEP)
	checksumOffset := optionalHeaderOffset + 64

	remainder := size % 4
	dataLen := size

	if remainder > 0 {
		dataLen = size + (4 - remainder)
		paddedBytes := make([]byte, 4-remainder)
		data = append(data, paddedBytes...)
	}

	for i := uint32(0); i < dataLen; i += 4 {
		// Saltiamo il campo del checksum
		if i == checksumOffset {
			continue
		}

		currentDword = binary.LittleEndian.Uint32(data[i:])

		checksum = (checksum & 0xffffffff) + uint64(currentDword) + (checksum >> 32)

		if checksum > max {
			checksum = (checksum & 0xffffffff) + (checksum >> 32)
		}
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = checksum + (checksum >> 16)
	checksum = checksum & 0xffff
	checksum += uint64(size)

	return uint32(checksum)
}