/// 2022 MicroSCOPE Contributors. See LICENSE

package main

import (
	_ "embed"
	"flag"
	"fmt"
	"microscope/analysis"
	"microscope/formats"
	"microscope/heuristics"
	"os"
	"time"
)

const (
	VERSION = "0.0.2-alpha"
)

//go:embed utils/output_template.html
var outputTemplateHTML string

//go:embed utils/output_template.txt
var outputTemplateTXT string

//go:embed utils/peid.txt
var PeIDFileContent string

func binaryOpen(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func main() {

	start := time.Now()

	fmt.Println("MicroSCOPE version " + VERSION)

	var fileName string
	var threshold int
	var dimensionsLimit int
	var format string

	// Flag da passare a linea di comando
	defaultFileName := ""
	flag.StringVar(&fileName, "f", defaultFileName, "Specifica il nome del file che si vuole analizzare.")
	flag.IntVar(&threshold, "t", 150, "Specifica il punteggio minimo sopra cui identificare un file malevolo")
	flag.IntVar(&dimensionsLimit, "limit", 1<<32, "Specifica la dimensione massima del file binario da analizzare")
	flag.StringVar(&format, "o", "html", "Specifica il formato del file di output dell'analisi (valori possibili html oppure txt)")
	flag.Parse()

	if fileName == "" {
		fmt.Println("Deve essere specificato un file binario da analizzare. Utilizza --f [nome del file] per specificarlo.")
		return
	}

	if threshold < 0 {
		fmt.Println("Il valore di threshold non può essere minore di 0.")
		return
	}

	// Apertura del file binario
	binaryFile, err := binaryOpen(fileName)
	if err != nil {
		fmt.Println("Errore nell'apertura del file " + err.Error())
		return
	}

	// Controllo dimensione del file
	fi, err := binaryFile.Stat()
	if err != nil {
		fmt.Println("Impossibile ottenere le dimensioni del file per il seguente motivo: " + err.Error())
		return
	}

	if fi.Size() > int64(dimensionsLimit) {
		fmt.Println("Dimensione del file è maggiore del limite consentito.")
		return
	}

	// Controlla se le dimensioni del binario sono minori del più piccolo file eseguibile mai stato creato (97 Byte)
	// Fonte: https://archive.ph/w01DO#selection-265.0-265.44
	if fi.Size() < 97 {
		fmt.Println("Il file è troppo piccolo per poter essere analizzato.")
		return
	}

	// Popola i campi per il file analizzato
	fileAnalyzed := formats.FileAnalyzed{}
	fileAnalyzed.Name = fi.Name()
	fileAnalyzed.Size = fi.Size()

	// Imposta alcuni file (peid.txt e l'output template)
	analysis.OutputTemplateHTML = outputTemplateHTML
	analysis.OutputTemplateTXT = outputTemplateTXT
	heuristics.PeIDFileContent = PeIDFileContent

	// Creo cartella results
	if _, err := os.Stat("./results"); os.IsNotExist(err) {
		os.Mkdir("./results", 0755)
	}

	// Ottengo il formato
	fileAnalyzed.OutputFormat = format
	fileAnalyzed.Threshold = threshold

	// Inizia l'analisi
	analysis.StartAnalysis(binaryFile, &fileAnalyzed)

	defer binaryFile.Close()

	// Stampa report finale

	fmt.Printf("Tempo di esecuzione: %s\n", time.Since(start))

}
