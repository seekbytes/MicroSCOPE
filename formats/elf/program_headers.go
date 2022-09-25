package elf

import (
	"encoding/binary"
	"fmt"
	"io"
)

func parseProgramHeaders(endianness binary.ByteOrder) interface{} {
	var programHeaderOffset uint64
	var programHeaderNumber uint16
	var programHeaderSize uint16
	switch header := ELFFile.Header.(type) {
	case Header32:
		programHeaderOffset = uint64(header.ProgramHeaderFileOffset)
		programHeaderNumber = header.ProgramEntryNumbers
		programHeaderSize = header.ProgramEntrySize
		return parseProgramHeader32(endianness, programHeaderOffset, programHeaderNumber, programHeaderSize)
	case Header64:
		programHeaderOffset = header.ProgramHeaderFileOffset
		programHeaderNumber = header.ProgramEntryNumbers
		programHeaderSize = header.ProgramEntrySize
		return parseProgramHeader64(endianness, programHeaderOffset, programHeaderNumber, programHeaderSize)
	}
	return nil
}

func parseProgramHeader32(endianness binary.ByteOrder, offset uint64, number uint16, size uint16) []ProgramHeader32 {
	programHeaders := make([]ProgramHeader32, number)

	for i := 0; i < int(number); i++ {
		offsetProgramHeader := int64(offset) + int64(i)*int64(size)
		_, err := reader.Seek(offsetProgramHeader, io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo" + err.Error())
			return nil
		}

		err = binary.Read(reader, endianness, &programHeaders[i])
		if err != nil {
			fmt.Println("Impossibile leggere la struttura ProgramHeader32")
			return nil
		}
	}

	return programHeaders
}

func parseProgramHeader64(endianness binary.ByteOrder, offset uint64, number uint16, size uint16) []ProgramHeader64 {
	programHeaders := make([]ProgramHeader64, number)

	for i := 0; i < int(number); i++ {
		offsetProgramHeader := int64(offset) + int64(i)*int64(size)
		_, err := reader.Seek(offsetProgramHeader, io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo" + err.Error())
			return nil
		}
		err = binary.Read(reader, endianness, &programHeaders[i])
		if err != nil {
			fmt.Println("Impossibile leggere la struttura ProgramHeader32")
			return nil
		}
	}

	return programHeaders
}
