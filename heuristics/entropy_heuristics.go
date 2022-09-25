package heuristics

import (
	"microscope/formats/elf"
	"microscope/formats/pe"
)

func CalculatePointsEntropy(sections interface{}) int {
	points := 0
	switch sectionsIterable := sections.(type) {
	case []*pe.Section:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomaly("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomaly("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
				}
			}
		}
		// Verifico la compatibilità con le signature di PeID
		ImportPEIDEntry(sectionsIterable)
	case []elf.Section32:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomaly("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomaly("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
				}
			}
		}
	case []elf.Section64:
		for i := 0; i < len(sectionsIterable); i++ {
			if sectionsIterable[i].Entropy > 6.5 {
				if sectionsIterable[i].Name == ".text" {
					InsertAnomaly("Le istruzioni sono offuscate.", 120)
				} else {
					InsertAnomaly("La sezione "+sectionsIterable[i].Name+" è offuscata.", 20)
				}
			}
		}
	}
	return points
}
