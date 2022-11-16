package heuristics

import (
	"microscope/formats/elf"
	"microscope/formats/pe"
)

var sectionsStandards int

func CalculatePointsEntropy(sections interface{}) int {
	points := 0
	var isProbablyCompressed bool

	switch sectionsIterable := sections.(type) {
	case []*pe.Section:

		var isTextSectionFound bool

		for i := 0; i < len(sectionsIterable); i++ {

			if sectionsIterable[i].Name == ".text" || sectionsIterable[i].Name == "CODE" {
				isTextSectionFound = true
			}

			checkSectionName(sectionsIterable[i].Name, false)

			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomalySection("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" è offuscata.", 20)
				}
			}

			// Compressione UPX
			if sectionsIterable[i].Name == "UPX0" {
				isProbablyCompressed = true
			}
			if isProbablyCompressed && sectionsIterable[i].Name == "UPX1" {
				InsertAnomalySection("Il file è compresso con UPX.", 40)
			}

			//
			if sectionsIterable[i].SizeOfRawData == 0 && sectionsIterable[i].VirtualSize == 0 {
				InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" ha dimensione fisica e virtuale pari a 0.", 20)
			}

			if sectionsIterable[i].SizeOfRawData-sectionsIterable[i].VirtualSize > 40000 {
				InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" ha una discrepanza importante tra la dimensione dichiarata e la dimensione virtuale.", 10)
			}

			if sectionsIterable[i].VirtualSize == 0 {
				InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" ha una dimensione virtuale pari a 0.", 20)
			}
		}

		if !isTextSectionFound {
			InsertAnomalySection("Non è stato possibile trovare la sezione .text", 20)
		}

		if sectionsStandards < 2 {
			InsertAnomalySection("Ci sono meno di 2 sezioni standard.", 20)
		}

		// Verifico la compatibilità con le signature di PeID
		ImportPEIDEntry(sectionsIterable)

	case []elf.Section32:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomalySection("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" è offuscata.", 20)
				}
			}

			if sectionsIterable[i].Name == "UPX0" {
				isProbablyCompressed = true
			}
			if isProbablyCompressed && sectionsIterable[i].Name == "UPX1" {
				InsertAnomalySection("Il file è compresso con UPX.", 40)
			}
		}
	case []elf.Section64:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomalySection("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomalySection("La sezione \""+sectionsIterable[i].Name+"\" è offuscata.", 20)
				}
			}

			if sectionsIterable[i].Name == "UPX0" {
				isProbablyCompressed = true
			}
			if isProbablyCompressed && sectionsIterable[i].Name == "UPX1" {
				InsertAnomalySection("Il file è compresso con UPX.", 40)
			}

		}
	}
	return points
}

func checkSectionName(name string, isElf bool) {
	if name == ".MPRESS1" {
		InsertAnomalySection("Il file è offuscato con MPRESS.", 100)
		return
	}

	if name == ".Upack" {
		InsertAnomalySection("Il file è offuscato con UPACK.", 100)
		return
	}

	if name == ".pelock" {
		InsertAnomalySection("Il file è offuscato con PELock.", 100)
		return
	}

	var defaultSectionName []string

	if isElf {
		defaultSectionsName := []string{
			".interp",
			".gnu.hash",
			".gnu.version",
			".gnu.version_r",
			".rela.dyn",
			".rela.plt",
			".init",
			".plt",
			".text",
			".fini",
			".rodata",
			".eh_frame_hdr",
			".eh_frame",
			".tbss",
			".ctors",
			".dtors",
			".dynamic",
			".got.plt",
			".data",
			".bss",
			".comment",
			".shstrtab",
		}
		defaultSectionName = defaultSectionsName
	} else {
		defaultSectionsName := []string{
			".text",
			".bss",
			".data",
			".rdata",
			".rsrc",
			".edata",
			".idata",
			".debug",
			".pdata",
			".reloc",
			".symtab",
			".tls",
			".eh_fram",
			".imrsiv",
			".CRT",
			"CODE",
			"BSS",
			"DATA",
			".didat",
			".gfids",
		}
		defaultSectionName = defaultSectionsName
	}

	isFound := false
	for i := 0; i < len(defaultSectionName); i++ {
		if name == defaultSectionName[i] {
			isFound = true
			// Conta quante sezioni sono valide, se esistono meno di 1 sezione valida allora inserisci l'anomalia
			sectionsStandards++
			break
		}
	}

	if !isFound {
		InsertAnomalySection("La sezione \""+name+"\" non è una sezione standard.", 10)
	}

}
