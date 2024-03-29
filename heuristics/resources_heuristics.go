package heuristics

import "microscope/formats/pe"

func CalculatePointsResources(resources []pe.Resource) {

	// Quante risorse incontriamo che sono file binari (o DLL)?
	binary := 0

	// Quante risorse incontriamo vuote (dimensione 0)?
	blank := 0

	// Quante risorse sono state
	entropy := 0

	for i := 0; i < len(resources); i++ {
		if resources[i].ContentType == "binary/pe" {
			binary++
		}

		if resources[i].Size == 0 {
			blank++
		}

		if resources[i].Entropy >= 6.6 && resources[i].ContentType != "image/png" {
			entropy++
		}
	}

	if entropy > 0 {
		InsertAnomalyOthers("Il binario contiene delle risorse offuscate.", 20*entropy)
	}

	if binary > 0 {
		InsertAnomalyOthers("Il binario contiene dei file eseguibili inseriti come risorse.", 20*binary)
	}

	if blank > 0 {
		InsertAnomalyOthers("Il binario presenta risorse vuote.", 10*blank)
	}

}
