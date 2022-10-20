package heuristics

import (
	"microscope/formats/elf"
)

func CalculatePointsSymbols(symbols []elf.Symbol) {
	ransomwareName := map[string]int{
		"open64":  15, // system call che è simile alla open però apre automaticamente il file con O_LARGEFILE
		"fopen64": 15,
	}

	for i := 0; i < len(symbols); i++ {
		symbolName := symbols[i].Name
		if pointToAdd, isFound := ransomwareName[symbolName]; isFound {
			InsertAnomalyImports("Il simbolo "+symbolName+" è compatibile con altri ransomware trovati.", pointToAdd)
		}
	}
}
