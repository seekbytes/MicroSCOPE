package heuristics

import "microscope/formats/pe"

func CalculatePointsSecurity(SecuritySection []pe.SecurityHeader) int {
	point := 0

	for i := 0; i < len(SecuritySection); i++ {
		if !SecuritySection[i].IsSigned {
			InsertAnomalyFileFormat("Il binario presenta delle firme ma sono invalide.", 50)
			break
		}
	}

	return point
}
