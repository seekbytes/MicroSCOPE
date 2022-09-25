package formats

import (
	"microscope/formats/elf"
	"microscope/formats/pe"
)

type FileAnalyzed struct {
	Name             string        // Nome del file
	Size             int64         // Dimensione del file
	Format           string        // Formato del file
	Architecture     string        // Architettura
	Score            int           // Punteggio
	ExtractedStrings []string      // Stringhe estratte
	Anomalies        []Anomaly     // Anomalie
	Hash             string        // Hash 256
	OutputFormat     string        // Formato del file di output dell'analisi
	PEInterface      pe.PEBINARY   // Puntatore al PEbinary se il formato è PE
	ELFInterface     elf.ELFBINARY // Puntatore all'elfbinary se il formato è ELF
	Threshold        int           // Threshold
	Raw              []byte
}

type Anomaly struct {
	Reason string
	Points int
}
