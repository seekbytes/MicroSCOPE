package heuristics

import (
	"fmt"
	"microscope/formats/elf"
)

func CheckELFHeader() {

	var elfHeader64 elf.Header64
	var ok bool

	elfHeader32, is32bit := FileAnalyzed.ELFInterface.Header.(elf.Header32)
	if !is32bit {
		elfHeader64, ok = FileAnalyzed.ELFInterface.Header.(elf.Header64)
		if !ok {
			fmt.Println("Impossibile")
			return
		}
	}

	if is32bit {
		if elfHeader32.HeaderSize == 0 {
			InsertAnomalyFileFormat("La dimensione dell'header non può essere 0.", 50)
		}

		sections, err := FileAnalyzed.ELFInterface.Sections.([]elf.Section32)
		if !err {
			fmt.Println("Impossibile")
			return
		}

		if len(sections) < int(elfHeader32.SectionEntryNumbers) {
			InsertAnomalyFileFormat("Il numero di sezioni non combacia con il numero di sezioni trovate all'interno dell'intestazione. ", 40)
		}

		if len(sections) == 0 {
			InsertAnomalyFileFormat("Il binario non contiene alcuna sezione.", 20)
		}

	} else {
		if elfHeader64.HeaderSize == 0 {
			InsertAnomalyFileFormat("La dimensione dell'header non può essere 0.", 50)
		}

		sections, err := FileAnalyzed.ELFInterface.Sections.([]elf.Section64)
		if !err {
			fmt.Println("Impossibile")
			return
		}

		if len(sections) < int(elfHeader64.SectionEntryNumbers) {
			InsertAnomalyFileFormat("Il numero di sezioni non combacia con il numero di sezioni trovate all'interno dell'intestazione. ", 40)
		}

		if len(sections) == 0 {
			InsertAnomalyFileFormat("Il binario non contiene alcuna sezione.", 20)
		}

	}

}
