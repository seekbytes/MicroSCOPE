package elf

type IDENT struct {
	Magic      [4]uint8 // -ELF
	Class      uint8    // Specifica se è un eseguibile a 32 bit (UNO) o 64 bit (DUE)
	Endianness uint8    // Specifica se è Little Endian o Big Endian (1 = 32 bit, 2 = 64 bit)
	Version    uint8    // Specifica la versione dell'header ELF
	OSABI      uint8    // Specifica la versione ABI dell'OS (generalmente è ZERO per SystemV)
	ABIVersion uint8    // Riservato: deve essere ZERO
	Padding    [6]uint8
	SizeIdent  uint8
}

type ELFBINARY struct {
	Ident          IDENT
	Header         interface{} // Un header tra Header32 o Header64
	SectionHeaders interface{} // Intestazioni delle sezioni: array di SectionHeader32 o SectionHeader64
	Sections       interface{} // Sezioni
	ProgramHeaders interface{}
	Symbols        []Symbol // Simboli
}

type Header32 struct {
	Type                    uint16
	Machine                 uint16
	Version                 uint32
	Entry                   uint32
	ProgramHeaderFileOffset uint32
	SectionHeaderFileOffset uint32
	Flags                   uint32
	HeaderSize              uint16
	ProgramEntrySize        uint16
	ProgramEntryNumbers     uint16
	SectionEntrySize        uint16
	SectionEntryNumbers     uint16
	StringSectionsName      uint16
}

type Header64 struct {
	Type                    uint16
	Machine                 uint16
	Version                 uint32
	Entry                   uint64
	ProgramHeaderFileOffset uint64
	SectionHeaderFileOffset uint64
	Flags                   uint32
	HeaderSize              uint16
	ProgramEntrySize        uint16
	ProgramEntryNumbers     uint16
	SectionEntrySize        uint16
	SectionEntryNumbers     uint16
	StringSectionsName      uint16
}

type SectionHeader32 struct {
	Name             uint32 // Indice della stringa del nome della sezione
	Type             uint32 // Tipo della sezione
	Flags            uint32 // Flags della sezione
	VirtualAddress   uint32 // Indirizzo virtuale in memoria
	Offset           uint32 // Offset della sezione
	Size             uint32 // Dimensione della sezione in bytes
	Link             uint32 //
	MiscInformation  uint32 // Informazioni varie in base al tipo di sezione
	AddressAlignment uint32 // Allineamento dell'indirizzo
	EntrySize        uint32 //
}

type SectionHeader64 struct {
	Name             uint32 // Nome della sezione
	Type             uint32 // Tipo della sezione
	Flags            uint64 // Flags della sezione
	VirtualAddress   uint64 // Indirizzo virtuale in memoria
	Offset           uint64 // Offset della sezione
	Size             uint64 // Dimensione della sezione in bytes
	Link             uint32 //
	MiscInformation  uint32 // Informazioni varie in base al tipo di sezione
	AddressAlignment uint64 // Allineamento dell'indirizzo
	EntrySize        uint64 //
}

type Section32 struct {
	Name    string
	Header  *SectionHeader32
	Raw     []byte
	Entropy float64
}

type Section64 struct {
	Name    string // Nome della sezione
	Header  *SectionHeader64
	Raw     []byte
	Entropy float64
}

type ProgramHeader32 struct {
	SegmentType    uint32
	Offset         uint32
	VirtualAddress uint32
	PaddingAddress uint32
	FileSize       uint32
	MemorySize     uint32
	Flags          uint32
	Alignment      uint32
}

type ProgramHeader64 struct {
	SegmentType    uint32
	Offset         uint32
	VirtualAddress uint64
	PaddingAddress uint64
	FileSize       uint64
	MemorySize     uint64
	Flags          uint64
	Alignment      uint64
}

type Symbol struct {
	Name        string
	Information byte
	Other       byte
	Index       uint32
	Value       int64
	Size        uint64
}

type SymbolEntry32 struct {
	NameIndex    uint32 // Indice del nome all'interno della string table
	Value        uint32 // Valore
	Size         uint32 // Dimensione del simbolo
	Information  uint8  // Informazione del tipo e del binding
	Other        uint8  // Riservato
	SectionIndex uint16 // Indice della sezione del simbolo
}

type SymbolEntry64 struct {
	NameIndex    uint32 // Indice del nome all'interno della string table
	Information  uint8  // Informazione del tipo e del binding
	Other        uint8  // Riservato
	SectionIndex uint16 // Indice della sezione del simbolo
	Value        uint64 // Valore
	Size         uint64 // Dimensione del simbolo

}
