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
	OutputFormat     string        // Formato del file prodotto dall'analisi
	PEInterface      pe.PEBINARY   // Puntatore al PEbinary se il formato è PE
	ELFInterface     elf.ELFBINARY // Puntatore all'elfbinary se il formato è ELF
	Instructions     []string      // Istruzioni
	Threshold        int           // Threshold
	Raw              []byte
}

type Anomaly struct {
	Reason string // Ragione dell'anomalia
	Points int    // Punteggio assegnato all'anomalia
	Type   uint   // Tipo di anomalia (1: difetti sul file, 2: imports/sysapi, 3: stringhe)
}
