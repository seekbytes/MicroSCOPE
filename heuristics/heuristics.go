package heuristics

import (
	"fmt"
	"microscope/formats"
	"strings"
)

var FileAnalyzed *formats.FileAnalyzed

func Execute(analyzed *formats.FileAnalyzed) {
	FileAnalyzed = analyzed
	// Verifica se il binario può essere stato scritto tramite GoLang oppure Python
	language := GuessLanguageByStrings(analyzed.ExtractedStrings)

	if language == "Go" {
		CalculatePointsStringGO(analyzed.ExtractedStrings)
	}

	if analyzed.Format == "PE" {
		var isDotNet bool
		if len(analyzed.PEInterface.Imports) == 1 {
			if analyzed.PEInterface.Imports[0].APICalled == "_CorExeMain" {
				isDotNet = true
				InsertAnomaly("Il programma è un file eseguibile .NET.", 0)
			}
		}

		// Binario Tradizionale
		// Euristica sulle intestazioni
		CheckHeaders()
		// Euristica sulle stringhe
		CalculatePointsStringPE(analyzed.ExtractedStrings, isDotNet)
		// Euristica sugli imports
		CalculatePointsImports(analyzed.PEInterface.Imports)
		// Euristica sull'entropia
		CalculatePointsEntropy(analyzed.PEInterface.Sections)

		// Euristica sui binari signed/unsigned
		CalculatePointsSecurity(analyzed.PEInterface.SecuritySection)
	}

	if analyzed.Format == "ELF" {
		// Euristica sull'entropia
		CalculatePointsEntropy(analyzed.ELFInterface.Sections)

		// Euristica sui simboli
		CalculatePointsSymbols(analyzed.ELFInterface.Symbols)

		// Euristica sulle stringhe
		CalculatePointsStringELF(analyzed.ExtractedStrings)
	}

	CalculateStrings(analyzed.ExtractedStrings)

}

func GuessLanguageByStrings(extractedStrings []string) string {
	points := 0

	golangstrings := map[string]int{
		"Go build":                     1,
		"/usr/lib/go/src/crypto/":      4,
		"/usr/lib/go/src/internal/cpu": 10,
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range golangstrings {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				fmt.Println(extractedStrings[i])
				points += pointsToAdd
			}
		}
	}

	if points != 0 {
		InsertAnomaly("Il binario è stato probabilmente scritto in Golang.", 0)
		return "Go"
	}

	points = 0

	pythonstrings := map[string]int{
		"python": 1,
	}

	for i := 0; i < len(extractedStrings); i++ {
		for stringToCompare, pointsToAdd := range pythonstrings {
			if strings.Contains(extractedStrings[i], stringToCompare) {
				fmt.Println(extractedStrings[i])
				points += pointsToAdd
			}
		}
	}

	if points != 0 {
		return "Python"
	}

	return ""

}
