package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"microscope/utils"
)

func readExports(virtualAddress uint32) {

	section := getSectionFromVirtualAddress(uint64(virtualAddress))

	if section == nil {
		fmt.Println("La sezione exports non esiste per questo binario.")
		return
	}

	offset := virtualAddress - section.VirtualAddress

	reader := bytes.NewReader(section.Raw)

	_, err := reader.Seek(int64(offset), io.SeekStart)
	if err != nil {
		fmt.Println("Errore nel seeking per il seguente motivo " + err.Error())
	}

	exportDirectory := ExportDirectory{}
	err = binary.Read(reader, binary.LittleEndian, &exportDirectory)

	if err != nil {
		fmt.Println("Impossibile leggere la struttura exportDirectory " + err.Error())
	}

	namesTableRVA := exportDirectory.NameRva - section.VirtualAddress
	ordinalsTableRVA := exportDirectory.OrdinalBase - section.VirtualAddress
	var ordinal uint16

	fileAnalyzed.ExportNameMap = make(map[string]*Export)
	fileAnalyzed.ExportOrdinalMap = make(map[int]*Export)

	// Per ogni entry della tabella degli exports
	for i := 0; i < int(exportDirectory.NumberOfName); i++ {

		//
		_, err = reader.Seek(int64(namesTableRVA+uint32(i*4)), io.SeekStart)
		if err != nil {
			fmt.Println("Errore nel seek per la tabella delle funzioni esportate")
			return
		}

		exportAddressTable := ExportAddressTable{}
		err = binary.Read(reader, binary.LittleEndian, &exportAddressTable)
		if err != nil {
			fmt.Println("Impossibile leggere la struttura ExportAddressTable per il seguente motivo : " + err.Error())
			return
		}

		name := utils.ReadString(section.Raw[exportAddressTable.ExportRva-section.VirtualAddress:])
		ordinal = binary.LittleEndian.Uint16(section.Raw[ordinalsTableRVA+uint32(i*2) : ordinalsTableRVA+uint32(i*2)+2])
		_, err = reader.Seek(int64(uint32(ordinal)*4+exportDirectory.AddressOfFunctions-section.VirtualAddress), io.SeekStart)

		if err != nil {
			fmt.Println("Impossibile eseguire il seek per la lettura della prossima riga.")
			return
		}

		exportOrdinalTable := ExportAddressTable{}
		err = binary.Read(reader, binary.LittleEndian, &exportOrdinalTable)
		if err != nil {
			fmt.Println("Impossibile leggere la struttura ExportAddressTable per il seguente motivo: " + err.Error())
			return
		}
		rva := exportOrdinalTable.ExportRva

		export := &Export{name, ordinal + uint16(exportDirectory.OrdinalBase), rva}
		fileAnalyzed.Exports = append(fileAnalyzed.Exports, export)
		fileAnalyzed.ExportNameMap[name] = export
		fileAnalyzed.ExportOrdinalMap[int(ordinal)] = export
	}
}
