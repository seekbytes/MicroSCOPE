package analysis

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"html/template"
	"io"
	"microscope/formats"
	"microscope/formats/elf"
	"microscope/formats/pe"
	"microscope/heuristics"
	"os"
	"strconv"
	"time"
)

const (
	FILE_HEADER_PHASE_1 = 5 // Numero di byte letti all'inizio della fase 1 (vedi documenti) per discriminare il file
)

var OutputTemplateHTML string
var OutputTemplateTXT string

func divide(a int, b int) int {
	return a / b
}

func PrintResult(Analyzed *formats.FileAnalyzed) {
	// lista delle funzioni passate al template
	funcMap := template.FuncMap{
		"now":                          time.Now,
		"divide":                       divide,
		"PEprintArchitecture":          pe.PrintArchitecture,
		"PEprintResource":              pe.PrintResource,
		"PEprintSubsystem":             pe.PrintSubsystem,
		"PEprintMajorOperatingVersion": pe.PrintMajorOperatingSystemVersion,
		"PEprintCharacteristics":       pe.PrintCharacteristic,
		"ELFprintMachine":              elf.PrintMachine,
		"ELFprintSectionType":          elf.PrintSectionType,
		"ELFprintFileType":             elf.PrintFileType,
	}

	if Analyzed.OutputFormat == "txt" {
		printTxt(*Analyzed)
	} else if Analyzed.OutputFormat == "html" {

		// carica un template html e popolalo con la struttura fileAnalyzed
		t := template.Must(template.New("output_template.html").Funcs(funcMap).Parse(OutputTemplateHTML))

		var processed bytes.Buffer

		err := t.Execute(&processed, Analyzed)
		if err != nil {
			fmt.Println("Non è stato possibile eseguire il template per questo motivo: " + err.Error())
			return
		}
		outputPath := "./results/" + Analyzed.Name + "_analysis.html"
		f, err := os.Create(outputPath)
		if err != nil {
			fmt.Println("Impossibile creare nuovo file.")
			return
		}
		w := bufio.NewWriter(f)
		_, err = w.WriteString(string(processed.Bytes()))
		if err != nil {
			fmt.Println("Impossibile scrivere il template sul file per il seguente errore: " + err.Error())
			return
		}
		err = w.Flush()
		if err != nil {
			fmt.Println("Impossibile rimuovere il contenuto dell'IOBuffer.")
			return
		}
	} else {
		fmt.Println("Formato file non valido.")
	}

	fmt.Println("Microscope risultato. ")
	fmt.Println("Formato file : " + Analyzed.Format)
	fmt.Println("Architettura : " + Analyzed.Architecture)
	fmt.Println("Dimensione del file " + strconv.FormatInt(Analyzed.Size, 10))
	fmt.Println("Punteggio " + strconv.FormatInt(int64(Analyzed.Score), 10))

	if Analyzed.Score > Analyzed.Threshold {
		fmt.Println("!!!!!RANSOMWARE!!!!")
	}

	if Analyzed.Score > Analyzed.Threshold/2 && Analyzed.Score < Analyzed.Threshold {
		fmt.Println("È un possibile malware.")
	}

}

func ReadContentFile(file *os.File) []byte {
	// Molto importante impostare l'offset del file dall'inizio altrimenti c'è il rischio che la io.ReadAll
	// legga dal punto in cui l'offset è rimasto dalla funzione analysis
	newPosition, err := file.Seek(0, io.SeekStart)

	if err != nil {
		fmt.Println("Errore durante l'impostazione dell'offset " + err.Error())
		return nil
	}

	if newPosition != 0 {
		fmt.Println("Errore durante l'impostazione dell'offset")
		return nil
	}

	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Impossibile leggere il contenuto del file per il seguente motivo " + err.Error())
		return nil
	}
	return content
}

func StartAnalysis(file *os.File, Analyzed *formats.FileAnalyzed) {

	// Controlla i primi FILE_HEADER_PHASE_1 byte di file
	var header [FILE_HEADER_PHASE_1]byte
	// Ritorna il numero di byte letti
	n, err := io.ReadFull(file, header[:])
	if err != nil || n != FILE_HEADER_PHASE_1 {
		fmt.Println("Impossibile leggere i primi 10 byte.")
		return
	}

	// Leggi contenuto del file
	Analyzed.Raw = ReadContentFile(file)
	h := sha256.New()
	h.Write(Analyzed.Raw)
	Analyzed.Hash = fmt.Sprintf("%x", h.Sum(nil))

	// Se il file contiene un possibile elf header, allora..
	if IsELFBinary(header) {
		Analyzed.Format = "ELF"
		// Procediamo con l'analisi dei segmenti ELF
		elf.ELFAnalysis(file, &Analyzed.ELFInterface)
		var machine uint16
		switch headerFields := Analyzed.ELFInterface.Header.(type) {
		case elf.Header32:
			machine = headerFields.Machine
		case elf.Header64:
			machine = headerFields.Machine
		}

		Analyzed.Architecture = elf.PrintMachine(machine)
	}

	// Altrimenti controlla se è un possibile binario PE
	if isPEBinary(header) {
		Analyzed.Format = "PE"
		// Procediamo con l'analisi del file PE
		pe.Analysis(&Analyzed.PEInterface, Analyzed.Raw)
		Analyzed.Architecture = pe.PrintArchitecture(Analyzed.PEInterface.COFFHeader.Machine)
	}

	if Analyzed.Format == "PE" || Analyzed.Format == "ELF" {
		// Estrai le stringhe
		Analyzed.ExtractedStrings = ExtractStrings(file, 6, 256, true)

		// Applica le euristiche
		heuristics.Execute(Analyzed)

		// Stampa il risultato
		PrintResult(Analyzed)
	} else {
		fmt.Println("Questo tipo di file non è al momento supportato da MicroSCOPE.")
	}
}

func IsELFBinary(content [FILE_HEADER_PHASE_1]byte) bool {
	// Controllo dei primi tre byte "ELF"
	if content[0] == 0x7f && content[1] == byte('E') && content[2] == byte('L') && content[3] == byte('F') {
		return true
	}

	return false
}

func isPEBinary(content [FILE_HEADER_PHASE_1]byte) bool {

	// TODO: Questa è una prima euristica molto veloce che consente subito di determinare se un file potrebbe essere un file PE oppure no
	// Rimangono da verificare tutti i casi limite
	// Potrebbe essere utile passare di nuovo il puntatore del file a questa funzione per cercare l'offset 0x3c che indica la struttura PE
	// e il successivo controllo sulla signature PE

	// Controlla lo stub per Microsoft MS-DOS (i primi due byte devono essere MZ dal nome del creatore del formato)
	if content[0] == byte('M') && content[1] == byte('Z') {
		return true
	}

	// Esistono anche binari che hanno la sigla "MZ" invertita

	if content[0] == byte('Z') && content[0] == byte('M') {
		return true
	}

	return false
}
