package elf

import (
	"encoding/binary"
	"fmt"
	"io"
	"microscope/utils"
)

func parseSections(endianness binary.ByteOrder) interface{} {

	var shnum uint16
	var numberSectionStringTable uint16
	switch header := ELFFile.Header.(type) {
	case Header32:
		shnum = header.SectionEntryNumbers
		numberSectionStringTable = header.StringSectionsName
		return parseSections32(endianness, shnum, numberSectionStringTable)
	case Header64:
		shnum = header.SectionEntryNumbers
		numberSectionStringTable = header.StringSectionsName
		return parseSections64(endianness, shnum, numberSectionStringTable)
	}

	if shnum == 0 {
		return nil
	}

	return nil
}

func parseSections64(endianness binary.ByteOrder, shnum uint16, table uint16) []Section64 {
	if shnum == 0 {
		fmt.Println("Questo binario non contiene alcuna sezione.")
		return nil
	}

	sections := make([]Section64, shnum)

	headers, ok := ELFFile.SectionHeaders.([]SectionHeader64)
	if !ok {
		fmt.Println("headers può essere solamente un array con sectionheader64. ")
		return nil
	}

	for i := 0; i < int(shnum); i++ {
		tmp := Section64{}
		if headers[i].Size != 0 {
			_, err := reader.Seek(int64(headers[i].Offset), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile effettuare il seek " + err.Error())
				return nil
			}
			buffer := make([]byte, headers[i].Size)
			err = binary.Read(reader, endianness, &buffer)
			if err != nil {
				fmt.Println("Impossibile leggere la sezione")
				return nil
			}
			tmp.Raw = buffer
			tmp.Entropy = utils.CalculateEntropy(tmp.Raw)
		} else {
			tmp.Entropy = 0
		}
		tmp.Header = &headers[i]
		sections[i] = tmp
	}

	stringTable := sections[table].Raw

	for i := 0; i < int(shnum); i++ {
		if headers[i].Size != 0 {
			sections[i].Name = utils.ReadStringFrom(stringTable, int(headers[i].Name))
		} else {
			sections[i].Name = "Not used"
		}
	}

	return sections
}

func parseSections32(endianness binary.ByteOrder, shnum uint16, table uint16) []Section32 {
	if shnum == 0 {
		fmt.Println("Questo binario non contiene alcuna sezione.")
		return nil
	}

	sections := make([]Section32, shnum)

	headers, ok := ELFFile.SectionHeaders.([]SectionHeader32)
	if !ok {
		fmt.Println("headers può essere solamente un array con sectionHeader32. ")
		return nil
	}

	for i := 0; i < int(shnum); i++ {
		tmp := Section32{}
		if headers[i].Size != 0 {
			_, err := reader.Seek(int64(headers[i].Offset), io.SeekStart)
			if err != nil {
				fmt.Println(err.Error())
			}
			buffer := make([]byte, headers[i].Size)
			binary.Read(reader, endianness, &buffer)
			tmp.Raw = buffer
			tmp.Entropy = utils.CalculateEntropy(tmp.Raw)
		} else {
			tmp.Entropy = 0
		}
		tmp.Header = &headers[i]
		sections[i] = tmp
	}

	stringTable := sections[table].Raw

	for i := 0; i < int(shnum); i++ {
		if headers[i].Size != 0 {
			sections[i].Name = utils.ReadStringFrom(stringTable, int(headers[i].Name))
		} else {
			sections[i].Name = "Not used"
		}
	}

	return sections
}

func parseSectionHeaders(endianness binary.ByteOrder) interface{} {
	var numberSections uint16
	var offsetSections uint64
	var sizeSection uint16
	switch header := ELFFile.Header.(type) {
	case Header32:
		numberSections = header.SectionEntryNumbers
		offsetSections = uint64(header.SectionHeaderFileOffset)
		sizeSection = header.SectionEntrySize
		return parseSectionHeaders32(endianness, numberSections, offsetSections, sizeSection)
	case Header64:
		numberSections = header.SectionEntryNumbers
		offsetSections = header.SectionHeaderFileOffset
		sizeSection = header.SectionEntrySize
		return parseSectionHeaders64(endianness, numberSections, offsetSections, sizeSection)
	}

	return nil
}

func parseSectionHeaders32(endianness binary.ByteOrder, numberSections uint16, offsetSections uint64, sizeSection uint16) []SectionHeader32 {
	if numberSections == 0 || sizeSection == 0 {
		fmt.Println("Questo file non presenta alcuna sezione")
		return nil
	}

	sectionsHeaders := make([]SectionHeader32, numberSections)

	for i := 0; i < int(numberSections); i++ {
		offset := offsetSections + uint64(i)*uint64(sizeSection)
		_, err := reader.Seek(int64(offset), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo: " + err.Error())
			return nil
		}
		err = binary.Read(reader, endianness, sectionsHeaders[i])
		if err != nil {
			fmt.Println("Impossibile leggere il SectionHeader")
			return nil
		}
	}
	return sectionsHeaders
}

func parseSectionHeaders64(endianness binary.ByteOrder, numberSections uint16, offsetSections uint64, sizeSection uint16) []SectionHeader64 {
	if numberSections == 0 || sizeSection == 0 {
		fmt.Println("Questo file non presenta alcuna sezione")
		return nil
	}

	sectionsHeaders := make([]SectionHeader64, numberSections)

	for i := 0; i < int(numberSections); i++ {
		// Attenzione che alcuni valori sono riservati (vedi Special Section Indexes)
		offset := offsetSections + uint64(i)*uint64(sizeSection)
		_, err := reader.Seek(int64(offset), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile effettuare un'operazione di Seek")
			return nil
		}
		err = binary.Read(reader, endianness, &sectionsHeaders[i])
		if err != nil {
			fmt.Println("Impossibile leggere il section Header")
			return nil
		}
	}
	return sectionsHeaders
}

func getSectionbyIndex(index uint32) interface{} {
	switch sections := ELFFile.Sections.(type) {
	case []Section32:
		if int(index) < len(sections) {
			return sections[index]
		}
		return nil
	case []Section64:
		if int(index) < len(sections) {
			return sections[index]
		}
		return nil
	}
	return nil
}
