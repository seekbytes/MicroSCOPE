package heuristics

import (
	"microscope/formats/elf"
	"microscope/formats/pe"
)

func CalculatePointsEntropy(sections interface{}) int {
	points := 0
	var isProbablyCompressed bool

	switch sectionsIterable := sections.(type) {
	case []*pe.Section:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomalySection("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomalySection("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
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
				InsertAnomalySection("La sezione "+sectionsIterable[i].Name+" ha dimensione fisica e virtuale pari a 0.", 20)
			}

			if sectionsIterable[i].SizeOfRawData-sectionsIterable[i].VirtualSize > 40000 {
				InsertAnomalySection("La sezione "+sectionsIterable[i].Name+" ha una discrepanza importante tra la dimensione dichiarata e la dimensione virtuale.", 10)
			}
		}
		// Verifico la compatibilità con le signature di PeID
		ImportPEIDEntry(sectionsIterable)

	case []elf.Section32:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomalySection("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomalySection("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
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
					InsertAnomalySection("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
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
