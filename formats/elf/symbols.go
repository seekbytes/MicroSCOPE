package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"microscope/utils"
)

func parseSymbols(endianness binary.ByteOrder) []Symbol {
	var symbolSection interface{}

	switch ELFFile.Header.(type) {
	case Header32:
		symbolSection = getSectionByType(11)
		return parseSymbols32(endianness, symbolSection)
	case Header64:
		symbolSection = getSectionByType(11)
		return parseSymbols64(endianness, symbolSection)
	}

	return nil
}

func parseSymbols64(endianness binary.ByteOrder, symbolTable interface{}) []Symbol {

	sections, ok := symbolTable.(Section64)

	if !ok {
		fmt.Println("La symbolTable deve essere di tipo Section64")
		return nil
	}

	if len(sections.Raw)%24 != 0 {
		fmt.Println("La dimensione della symbol table deve essere un multiplo di 16.")
		return nil
	}

	stringData := getSectionbyIndex(sections.Header.Link)
	stringTable, ok := stringData.(Section64)
	if !ok {
		fmt.Println("La stringTable deve essere di tipo Section64")
		return nil
	}

	symbolTableReader := bytes.NewReader(sections.Raw)

	var skipped [24]byte
	err := binary.Read(symbolTableReader, endianness, &skipped)
	if err != nil {
		fmt.Println("Impossibile leggere 24 byte per il seguente motivo: " + err.Error())
		return nil
	}

	symbols := make([]SymbolEntry64, len(sections.Raw)/24)
	GlobalSymbols := make([]Symbol, len(sections.Raw)/24)
	var tmp SymbolEntry64
	i := 0
	for symbolTableReader.Len() > 0 {
		err := binary.Read(symbolTableReader, endianness, &tmp)
		if err != nil {
			fmt.Println("Impossibile leggere la struttura SymbolEntry64 " + err.Error())
			return nil
		}
		symbols[i] = tmp
		str := utils.ReadStringFrom(stringTable.Raw, int(tmp.NameIndex))
		GlobalSymbols[i] = Symbol{
			Name:        str,
			Information: tmp.Information,
			Other:       tmp.Other,
			Index:       uint32(tmp.SectionIndex),
			Value:       int64(tmp.Value),
			Size:        tmp.Size,
		}
		i++
	}

	return GlobalSymbols
}

func parseSymbols32(endianness binary.ByteOrder, symbolTable interface{}) []Symbol {
	sections, ok := symbolTable.(Section32)

	if !ok {
		fmt.Println("La symbolTable deve essere di tipo Section32")
		return nil
	}

	if len(sections.Raw)%16 != 0 {
		fmt.Println("La dimensione della symbol table deve essere un multiplo di 16.")
		return nil
	}

	stringData := getSectionbyIndex(sections.Header.Link)
	stringTable, ok := stringData.(Section32)
	if !ok {
		fmt.Println("La stringTable deve essere di tipo Section32")
		return nil
	}

	symbolTableReader := bytes.NewReader(sections.Raw)

	var skipped [16]byte
	err := binary.Read(symbolTableReader, endianness, &skipped)

	if err != nil {
		fmt.Println("Impossibile leggere 16 byte per il seguente motivo " + err.Error())
		return nil
	}

	symbols := make([]SymbolEntry64, len(sections.Raw)/16)
	GlobalSymbols := make([]Symbol, len(sections.Raw)/16)
	var tmp SymbolEntry64
	i := 0
	for symbolTableReader.Len() > 0 {
		err := binary.Read(symbolTableReader, endianness, &tmp)
		if err != nil {
			fmt.Println("Impossibile leggere SymbolEntry64")
			return nil
		}
		symbols[i] = tmp
		str := utils.ReadStringFrom(stringTable.Raw, int(tmp.NameIndex))
		GlobalSymbols[i] = Symbol{
			Name:        str,
			Information: tmp.Information,
			Other:       tmp.Other,
			Index:       uint32(tmp.SectionIndex),
			Value:       int64(tmp.Value),
			Size:        tmp.Size,
		}
		i++
	}

	return GlobalSymbols
}
