package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

var reader *bytes.Reader
var ELFFile *ELFBINARY

func ELFAnalysis(file *os.File, elfbinary *ELFBINARY) {

	ELFFile = elfbinary

	// Resetta la posizione dell'offset del reader file per incominciare la lettura dall'inizio
	newPosition, err := file.Seek(0, io.SeekStart)

	if err != nil {
		fmt.Println("Errore durante l'impostazione dell'offset " + err.Error())
	}

	if newPosition != 0 {
		fmt.Println("Errore durante l'impostazione dell'offset")
	}

	// Leggi contenuto del file
	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Impossibile leggere il contenuto del file per il seguente motivo " + err.Error())
		return
	}

	reader = bytes.NewReader(content)
	var Elfident IDENT
	err = binary.Read(reader, binary.LittleEndian, &Elfident)

	if err != nil {
		fmt.Println("Errore nella lettura della prima parte dell'intestazione ELF")
		return
	}

	// Lettura dei magic bytes
	// Il primo byte è 0x7f
	if Elfident.Magic[0] != 0x7f || Elfident.Magic[1] != byte('E') || Elfident.Magic[2] != byte('L') || Elfident.Magic[3] != byte('F') {
		fmt.Println("Impossibile verificare i magic bytes, il file non è un file ELF.")
		return
	}

	var is64bit bool

	// is64bit --> per verificare se è a 64 bit
	if Elfident.Class == ARCHITECTURE_32 {
		is64bit = false
	} else if Elfident.Class == ARCHITECTURE_64 {
		is64bit = true
	}

	// isEndian
	var binaryEndianness binary.ByteOrder
	if Elfident.Endianness == 1 {
		binaryEndianness = binary.LittleEndian
	} else if Elfident.Endianness == 2 {
		binaryEndianness = binary.BigEndian
	} else {
		fmt.Println("Questo tipo di file non è supportato.")
		return
	}

	if Elfident.Version != VERSION_CURRENT {
		fmt.Println("Solo i file ELF versione 1 possono essere analizzati.")
		return
	}

	if Elfident.ABIVersion != 0 {
		fmt.Println("Attenzione, il campo ABIVersion è obsoleto e deve essere impostato a 0.")
	}

	ELFFile.Ident = Elfident

	if is64bit {
		ELFFile.Header = parseHeader64(binaryEndianness)
	} else {
		ELFFile.Header = parseHeader32(binaryEndianness)
	}

	ELFFile.SectionHeaders = parseSectionHeaders(binaryEndianness)
	ELFFile.Sections = parseSections(binaryEndianness)
	ELFFile.ProgramHeaders = parseProgramHeaders(binaryEndianness)
	ELFFile.Symbols = parseSymbols(binaryEndianness)
}

func getSectionByType(symbolType uint32) interface{} {

	switch sections := ELFFile.Sections.(type) {
	case []Section32:
		for i := 0; i < len(sections); i++ {
			if sections[i].Header.Type == symbolType {
				return sections[i]
			}
		}
		return nil
	case []Section64:
		for i := 0; i < len(sections); i++ {
			if sections[i].Header.Type == symbolType {
				return sections[i]
			}
		}
		return nil
	}

	return nil
}

func parseHeader32(binaryEndianness binary.ByteOrder) Header32 {
	var Header Header32
	err := binary.Read(reader, binaryEndianness, &Header)
	if err != nil {
		fmt.Println("Impossibile leggere l'header")
		return Header32{}
	}

	if Header.Type != 2 {
		fmt.Println("Per ora MicroSCOPE analizza soltanto i file eseguibili.")
		return Header32{}
	}

	return Header
}

func parseHeader64(binaryEndianness binary.ByteOrder) Header64 {
	var Header Header64

	err := binary.Read(reader, binaryEndianness, &Header)
	if err != nil {
		fmt.Println("Impossibile leggere l'header")
		return Header64{}
	}

	if Header.Type != 2 {
		fmt.Println("Per ora MicroSCOPE analizza soltanto i file eseguibili.")
		return Header64{}
	}

	return Header
}
