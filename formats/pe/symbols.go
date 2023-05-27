package pe

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Symbol Table

type COFFSymbol struct {
	Name               [8]byte // Nome del simbolo
	Value              int32   // Valore associato al symbolo, dipende dai campi SectionNumber e StorageClass
	SectionNumber      int16   // Identifica la sezione
	Type               uint16  // Rappresenta il tipo. Valori possibili sono 0x20 (funzione) o 0 (non è una funzione)
	StorageClass       uint8   //
	NumberOfAuxSymbols uint8   // Simboli ausiliari
}

type COFFTable struct {
	SymbolTable       []COFFSymbol
	StringTable       []string
	StringTableOffset uint32
	StringTableO      map[uint32]string // Associa l'offset del simbolo al nome del simbolo
}

func readSymbolTable() {

	// Puntatore alla tabella dei simboli
	symbolTablePointer := fileAnalyzed.COFFHeader.PointerToSymbolTable
	if symbolTablePointer == 0 {
		fmt.Println("La symbol table non esiste per questo binario")
		return
	}

	symbolNumber := fileAnalyzed.COFFHeader.NumberOfSymbols
	if symbolNumber == 0 {
		fmt.Println("Non esiste alcun simbolo.")
	}

	symbols := make([]COFFSymbol, symbolNumber)
	offset := symbolTablePointer

	for i := 0; i < int(symbolNumber); i++ {
		_, err := reader.Seek(int64(offset), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile eseguire il seek per il seguente motivo: " + err.Error())
			return
		}

		err = binary.Read(reader, binary.LittleEndian, &symbols[i])
		if err != nil {
			fmt.Println("Impossibile leggere il COFF symbol " + err.Error())
			return
		}

		offset += uint32(binary.Size(COFFSymbol{}))
	}

	parseStringTable()

}

func parseStringTable() {
	StringOffsetTable := make(map[uint32]string)
	SymbolTablePointer := fileAnalyzed.COFFHeader.PointerToSymbolTable
	NumberSymbols := fileAnalyzed.COFFHeader.NumberOfSymbols

	OffsetSkip := int(SymbolTablePointer) + binary.Size(COFFSymbol{})*int(NumberSymbols)
	_, err := reader.Seek(int64(OffsetSkip), io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile eseguire il seek per il seguente motivo: " + err.Error())
		return
	}

	var tableSize uint32
	err = binary.Read(reader, binary.LittleEndian, &tableSize)

	var stringsExtractedFromCOFF []string
	OffsetSkip = OffsetSkip + 4
	fmt.Println(tableSize)

	for OffsetSkip < int(SymbolTablePointer)+int(tableSize) {
		strTmp := ""
		_, err := reader.Seek(int64(OffsetSkip), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo " + err.Error())
			return
		}
		length := 0
		for i := 0; i < 0x50; i++ {
			var tmpByte byte
			err = binary.Read(reader, binary.LittleEndian, &tmpByte)
			if err != nil {
				fmt.Println("Impossibile leggere la stringTable")
				return
			}

			if tmpByte == 0 {
				break
			}

			strTmp += string(tmpByte)
			length++
		}

		StringOffsetTable[uint32(OffsetSkip)] = strTmp
		OffsetSkip += length + 1
		stringsExtractedFromCOFF = append(stringsExtractedFromCOFF, strTmp)
	}

}
