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
			InsertAnomalyFileFormat("Non possono esserci sezioni \"nascoste\" ", 40)
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

		if len(sections) < int(elfHeader32.SectionEntryNumbers) {
			InsertAnomalyFileFormat("Non possono esserci sezioni \"nascoste\" ", 40)
		}
	}

}
