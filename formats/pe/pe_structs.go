package pe

import "go.mozilla.org/pkcs7"

// TODO: Spiega i vari campi

// PEBINARY : Struttura che contiene tutti i campi del file PE analizzato
type PEBINARY struct {
	DosHeader        *DosHeaderT
	COFFHeader       COFFHeaderT
	OptionalHeader   interface{}
	Is64bit          bool
	Header           *Section
	Sections         []*Section
	DataDirectories  [16]ImageDataDirectory
	Exports          []*Export
	ExportNameMap    map[string]*Export
	ExportOrdinalMap map[int]*Export
	Imports          []*ImportInfo
	Resource         []Resource
	DebugSections    []DebugDirectory
	RichHeader       RichHeader
	SecuritySection  []SecurityHeader
	Instructions     []string
}

// DosHeaderT (lasciata per motivi di retro compatibilità legacy per tutti i file PE)
type DosHeaderT struct {
	MagicDos                   uint16 // 'MZ' o 'ZM' utilizzati per controllare se è un file binario valido (campo e_lfanew)
	BytesOnLastPage            uint16
	PagesInFile                uint16
	Relocations                uint16
	SizeOfHeader               uint16
	MinExtra                   uint16
	MaxExtra                   uint16
	InitialSS                  uint16
	InitialSP                  uint16
	Checksum                   uint16
	InitialIP                  uint16
	InitialCS                  uint16
	FileAddressRelocationTable uint16
	Overlay                    uint16
	Reserved                   [4]uint16
	OemId                      uint16
	OemInfo                    uint16
	Reserved2                  [10]uint16
	AddressExeOffset           uint32 // Offset che indica l'inizio dell'intestazione PE
}

// COFFHeaderT è una struttura dati basata sul tipo COFF (Common Object File Format), indica il numero di sezioni
// presenti all'interno del binario
type COFFHeaderT struct {
	Machine              uint16 // Architettura target del binario
	NumberOfSections     uint16 // Numero di sezioni del binario
	TimeDateStamp        uint32 // Timestamp della compilazione
	PointerToSymbolTable uint32 // Puntatore alla tabella dei simboli (deprecato, deve essere 0)
	NumberOfSymbols      uint32 // Numero di simboli contenuti nella tabella (deprecato, deve essere 0)
	SizeOfOptionalHeader uint16 // Dimensione dell'header successivo a questo
	Characteristics      uint16 // Un insieme di bit che indica le caratteristiche del binario
}

type ImageDataDirectory struct {
	VirtualAddress uint32 // Indirizzo virtuale che punta all'inizio della sezione
	Size           uint32 // Dimensione della DataDirectory
}

type PEOptionalHeaderT struct {
	MajorLinkerVersion          uint8 // Versione del compilatore
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32 // Dimensione della sezione .text
	SizeOfInitializedData       uint32 // Dimensione della sezione .data
	SizeOfUninitializedData     uint32 // Dimensione della sezione dei dati non inizializzati
	AddressOfEntryPoint         uint32 // Puntatore alla funzione "main". Per le librerie, questo campo è zero.
	BaseOfCode                  uint32 // Puntatore all'inizio della sezione .text
	BaseOfData                  uint32 // Puntatore all'inizio della sezione .data
	ImageBase                   uint32 // Indirizzo "preferibile" del primo byte dell'immagine in memoria.
	SectionAlignment            uint32 // Allineamento applicato alle sezioni in bytes nella memoria
	FileAlignment               uint32 // Allineamento applicato ai dati grezzi delle sezioni nel file
	MajorOperatingSystemVersion uint16 // Versione del sistema operativo target del binario
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16 // Versione del binario
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16 // versione del subsystem
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32 // Riservato, deve essere zero
	SizeOfImage                 uint32 // Dimensione del binario
	SizeOfHeaders               uint32 // Dimensione dell'intestazione del binario
	Checksum                    uint32 // Checksum
	Subsystem                   uint16 // Tipo di subsystem indicato per l'esecuzione del binario
	DllCharacteristics          uint16 // Altre caratteristiche definite per l'eseguibile
	SizeOfStackReserve          uint32 // Numero di bytes riservato allo spazio aggiuntivo dello stack
	SizeOfStackCommit           uint32 // Numero di bytes riservato allo stack all'inizio dell'esecuzione
	SizeOfHeapReserve           uint32 // Numero di bytes riservato allo spazio aggiuntivo dell'heap
	SizeOfHeapCommit            uint32 // Numero di bytes riservato all'heap all'inizio dell'esecuzione
	LoaderFlags                 uint32 // Obsoleto
	NumberOfRvaAndSizes         uint32 // Numero di directory entry
}

// PEPOptionalHeaderT è una struttura OptionalHeaderT per i file PE+ (64 bit). Presenta gli stessi campi
// dell'OptionalHeader per i binari a 32 bit, ma alcuni campi sono stati aumentati di dimensione.
type PEPOptionalHeaderT struct {
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	Checksum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type SectionHeader struct {
	Name                 [8]byte // Nome della sezione
	VirtualSize          uint32  // Dimensione totale della sezione quando è caricata in memoria.
	VirtualAddress       uint32  // Indirizzo del primo byte relativo all'immagine caricata in memoria
	SizeOfRawData        uint32  // Dimensione dei dati inizializzati nel disco. Deve essere un multiplo di FileAlignment
	PointerToRawData     uint32  // Il puntatore alla prima pagina della sezione del file COFF.
	PointerToRelocations uint32  // Puntatore all'inizio delle entry di rilocazione della sezione.
	PointerToLineNumbers uint32  //
	NumberOfRelocations  uint16  // Numero di rilocazioni all'interno del file
	NumberOfLineNumbers  uint16
	Characteristics      uint32 // Un insieme di bit che mostra le caratteristiche della SectionHeader
}

// Section: sezione del file PE
type Section struct {
	Name                 string
	Entropy              float64
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Raw                  []byte
}

// Export

type ExportDirectory struct {
	Characteristics       uint32 // In genere tutti zero per PE, campo riservato
	TimeDateStamp         uint32 // data di creazione
	MajorVersion          uint16 // Riservato: zero
	MinorVersion          uint16 // Riservato: zero
	NameRva               uint32 // RVA che punta al nome del modulo
	OrdinalBase           uint32 // Numero che va sommato all'indice per ottenere l'ordinal della funzione
	NumberOfFunctions     uint32 // Numero di funzioni esportate dal modulo
	NumberOfName          uint32 // Indica il numero di funzioni esportate con il nome
	AddressOfFunctions    uint32 // RVA che punta a un array contenente gli entry point di ogni funzione
	AddressOfNames        uint32 // RVA che punta a un array contenente i vari nomi delle funzioni
	AddressOfNameOrdinals uint32 // RVA per un array contenente gli ordinals delle funzioni
}

type ExportAddressTable struct {
	ExportRva  uint32
	ForwardRva uint32
}

type Export struct {
	Name    string
	Ordinal uint16
	Rva     uint32
}

// Import

type ImportDirectory struct {
	ImportLookupTableRVA  uint32
	TimeDataStamp         uint32
	ForwarderChain        uint32
	NameRVA               uint32
	ImportAddressTableRVA uint32
}

type ImportInfo struct {
	DllName   string
	APICalled string
	Offset    uint32
	Ordinal   uint16
	Thunk     uint32
}

// Resource

type ResourceDirectory struct {
	Characteristics      uint32 // Riservato: 0
	TimeDateStamp        uint32 // Tempo di creazione delle risorse
	MajorVersion         uint16 //
	MinorVersion         uint16
	NumberOfNamedEntries uint16 // numero di directory entries con un nome
	NumberOfIDEntries    uint16 // numero di directory entries con un ID
}

// ResourceDirectoryEntry rappresenta una entry all'interno della ResourceDirectory
type ResourceDirectoryEntry struct {
	Name         uint32
	OffsetToData uint32
}

type ResourceDataEntry struct {
	Offset   uint32
	Size     uint32
	Codepage uint32
	Reserved uint32 // Riservato, deve essere zero
}

type ResourceDirString struct {
	Length     uint16
	NameString byte
}

type Resource struct {
	Name          string
	Offset        uint64
	Size          uint64
	Content       []byte
	Type          int
	ContentType   string
	TimedateStamp uint32
	Entropy       float64
}

// CompID è una struttura che riporta le informazioni del compilatore all'interno del RichHeader.
type CompID struct {
	MinorCV uint16 // La versione del compilatore utilizzato (minor compiler version)
	ProdID  uint16 // Informazioni sul tipo di compilatore utilizzato
	Count   uint32 // Counter che indica quante volte l'oggetto è stato referenziato da questo file
	Raw     uint32 // La struttura raw
}

// RichHeader: composto da una chiave in XOR, una serie di CompID che identificano il tipo di compilatore se possibile
type RichHeader struct {
	XORKey  uint32
	CompIDs []CompID
	Raw     []byte
}

// Structs per il Debug

type REPRO struct {
	Size uint32
	Hash []byte
}

type VCFeature struct {
	PreVC11 uint32
	CCpp    uint32
	Gs      uint32
	Sdl     uint32
	GuardN  uint32
}

type PGOItem struct {
	Rva  uint32
	Size uint32
	Name string
}

type PGO struct {
	Signature uint32 // _IMAGE_POGO_INFO
	Entries   []PGOItem
}

type DebugDirectory struct {
	Characteristics  uint32 // Caratteristiche della sezione
	TimeDatestamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32 // Tipo di debug directory
	SizeOfData       uint32 // Dimensioni
	AddressOfRawData uint32
	PointerToRawData uint32
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type DebugCodeViewPDB7 struct {
	CodeViewSignature uint32 // 'RSDS'
	GUIDSignature     GUID   // Identificatore che cambia a seconda dell'eseguibile
	Age               uint32 //
	PDBFileName       string // Nome del file PDB
}

type DebugCodeViewPDB2 struct {
	CodeViewSignature uint32 // 'NB10'
	OffSet            uint32 // Offset del CodeView
	Signature         uint32
	Age               uint32
	PDBFileName       string
}

// Security

type WinCertificate struct {
	Length          uint32 // Lunghezza del certificato
	Revision        uint16 // "Revisione" del certificato (MSDN cita solamente 0x0200 come unica versione), mantenuta per legacy
	CertificateType uint16 // Tipo di certificato, mantenuta per legacy
}

type SecurityHeader struct {
	Header     WinCertificate
	Content    *pkcs7.PKCS7
	IsSigned   bool
	ReasonFail string
}

// APISET

type ApiSetHeader3 struct {
	Version         uint32 // Versione (2 per Windows 7, 4 per Windows 8 e 6 per Windows 10)
	Size            uint32 // Dimensione
	Sealed          uint32 // Indica se la mappa è
	NumberOfApiSets uint32 //
	NamesOffset     uint32 // Offset ai valori delle apiset
	TableOffset     uint32 // Offset alla tabella
	Multiplier      uint32 // Moltiplicatore da utilizzare quando si computa l'hash
}

type ApiSetNameEntry struct {
	Sealed        uint32
	Offset        uint32
	Ignored       uint32
	Size          uint32
	HostOffset    uint32
	NumberOfHosts uint32
}

type ApiSetValueEntry struct {
	Ignored     uint32
	NameOffset  uint32
	NameLength  uint32
	ValueOffset uint32
	ValueLength uint32
}
