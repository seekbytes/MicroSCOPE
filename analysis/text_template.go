package analysis

import (
	"bufio"
	"bytes"
	"fmt"
	"microscope/formats"
	"microscope/formats/elf"
	"microscope/formats/pe"
	"os"
	"text/template"
	"time"
)

func printTxt(Analyzed formats.FileAnalyzed) {

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

	// carica un template .txt e popolalo con la struttura fileAnalyzed
	t := template.Must(template.New("output_template.txt").Funcs(funcMap).Parse(OutputTemplateTXT))
	var processed bytes.Buffer

	err := t.Execute(&processed, Analyzed)
	if err != nil {
		fmt.Println("Non è stato possibile eseguire il template per questo motivo: " + err.Error())
		return
	}
	outputPath := "./results/" + Analyzed.Name + "_analysis.txt"
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
}
