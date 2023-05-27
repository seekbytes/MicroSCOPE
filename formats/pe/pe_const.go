package pe

import "strings"

const (
	MAGIC_MSDOS    = 0x5a4d
	MAGIC_PE       = 0x4550
	MAGIC_PE_32BIT = 0x10b
	MAGIC_PE_64BIT = 0x20b
)

// Costanti per le piattaforme target da cui poter eseguire il binario (campo "Machine").
const (
	IMAGE_FILE_MACHINE_UNKNOWN     = 0x0    // Ogni macchina è valida
	IMAGE_FILE_MACHINE_AM33        = 0x1d3  // Matsushita AM33
	IMAGE_FILE_MACHINE_AMD64       = 0x8664 // x64
	IMAGE_FILE_MACHINE_ARM         = 0x1c0  // ARM little endian
	IMAGE_FILE_MACHINE_ARM64       = 0xaa64 // ARM64 little endian
	IMAGE_FILE_MACHINE_ARMNT       = 0x1c4  // ARM Thumb-2 little endian
	IMAGE_FILE_MACHINE_EBC         = 0xebc  // EFI byte code
	IMAGE_FILE_MACHINE_I386        = 0x14c  // Intel 386 or later processors and compatible processors
	IMAGE_FILE_MACHINE_IA64        = 0x200  // Intel Itanium processor family
	IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232 // LoongArch 32-bit processor family
	IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264 // LoongArch 64-bit processor family
	IMAGE_FILE_MACHINE_M32R        = 0x9041 // Mitsubishi M32R little endian
	IMAGE_FILE_MACHINE_MIPS16      = 0x266  // MIPS16
	IMAGE_FILE_MACHINE_MIPSFPU     = 0x366  // MIPS with FPU
	IMAGE_FILE_MACHINE_MIPSFPU16   = 0x466  // MIPS16 with FPU
	IMAGE_FILE_MACHINE_POWERPC     = 0x1f0  // Power PC little endian
	IMAGE_FILE_MACHINE_POWERPCFP   = 0x1f1  // Power PC with floating point support
	IMAGE_FILE_MACHINE_R4000       = 0x166  // MIPS little endian
	IMAGE_FILE_MACHINE_RISCV32     = 0x5032 // RISC-V 32-bit address space
	IMAGE_FILE_MACHINE_RISCV64     = 0x5064 // RISC-V 64-bit address space
	IMAGE_FILE_MACHINE_RISCV128    = 0x5128 // RISC-V 128-bit address space
	IMAGE_FILE_MACHINE_SH3         = 0x1a2  // Hitachi SH3
	IMAGE_FILE_MACHINE_SH3DSP      = 0x1a3  // Hitachi SH3 DSP
	IMAGE_FILE_MACHINE_SH4         = 0x1a6  // Hitachi SH4
	IMAGE_FILE_MACHINE_SH5         = 0x1a8  // Hitachi SH5
	IMAGE_FILE_MACHINE_THUMB       = 0x1c2  // Thumb
	IMAGE_FILE_MACHINE_WCEMIPSV2   = 0x169  // MIPS little-endian WCE v2
)

// Campo subsystem
const (
	IMAGE_SUBSYSTEM_UNKNOWN                  = 0  // An unknown subsystem
	IMAGE_SUBSYSTEM_NATIVE                   = 1  // Device drivers and native Windows processes
	IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2  // The Windows graphical user interface (GUI) subsystem
	IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3  // The Windows character subsystem
	IMAGE_SUBSYSTEM_OS2_CUI                  = 5  // The OS/2 character subsystem
	IMAGE_SUBSYSTEM_POSIX_CUI                = 7  // The Posix character subsystem
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8  // Native Win9x driver
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9  // Windows CE
	IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10 // An Extensible Firmware Interface (EFI) application
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11 // An EFI driver with boot services
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12 // An EFI driver with run-time services
	IMAGE_SUBSYSTEM_EFI_ROM                  = 13 // An EFI ROM image
	IMAGE_SUBSYSTEM_XBOX                     = 14 // XBOX
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16 // Windows boot application.
)

const (
	IMAGE_RESOURCE_NAME_IS_STRING    = 0x80000000
	IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000
)

const (
	RT_UNKNOWN        = 0
	RT_CURSOR         = 1
	RT_BITMAP         = 2
	RT_ICON           = 3
	RT_MENU           = 4
	RT_DIALOG         = 5
	RT_STRING         = 6
	RT_FONTDIR        = 7
	RT_FONT           = 8
	RT_ACCELERATORS   = 9
	RT_RCDATA         = 10
	RT_MESSAGETABLE   = 11
	RT_GROUP_CURSOR   = 12
	RT_GROUP_ICON     = 14
	RT_VERSION        = 16
	RT_INCLUDE_DIALOG = 17
	RT_PLUG_PLAY      = 19
	RT_VXD            = 20
	RT_ANT_CURSOR     = 21
	RT_ANT_ICON       = 22
	RT_HTML_PAGES     = 23
	RT_CONFIG_FILES   = 24
)

// Campo Characteristics DDL per il futuro
const (
	IMAGE_DDLCHARACTERISTICS_RESERVED_1            = 0x0001
	IMAGE_DDLCHARACTERISTICS_RESERVED_2            = 0x0002
	IMAGE_DDLCHARACTERISTICS_RESERVED_4            = 0x0004
	IMAGE_DDLCHARACTERISTICS_RESERVED_8            = 0x0008
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020 // Image can handle a high entropy 64-bit virtual address space.
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040 // DLL can be relocated at load time.
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080 // Code Integrity checks are enforced.
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100 // Image is NX compatible.
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200 // Isolation aware, but do not isolate the image.
	IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400 // Does not use structured exception (SE) handling. No SE handler may be called in this image.
	IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800 // Do not bind the image.
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER          = 0x1000 // Image must execute in an AppContainer.
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000 // A WDM driver.
	IMAGE_DLLCHARACTERISTICS_GUARD_CF              = 0x4000 // Image supports Control Flow Guard.
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000 // Terminal Server aware.
)

// Flags Section
const (
	IMAGE_SECTIONFLAGS_RESERVED_0           = 0x00000000
	IMAGE_SECTIONFLAGS_RESERVED_1           = 0x00000001
	IMAGE_SECTIONFLAGS_RESERVED_2           = 0x00000002
	IMAGE_SECTIONFLAGS_RESERVED_4           = 0x00000004
	IMAGE_SECTIONFLAGS_TYPE_NO_PAD          = 0x00000008
	IMAGE_SECTIONFLAGS_RESERVED_10          = 0x00000010 // Reserved for future use.
	IMAGE_SECTIONFLAGS_CNT_CODE             = 0x00000020 // The section contains executable code.
	IMAGE_SECTIONFLAGS_CNT_INITIALIZED_DATA = 0x00000040 // The section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA        = 0x00000080 // The section contains uninitialized data.
	IMAGE_SCN_LNK_OTHER                     = 0x00000100 // Reserved for future use.
	IMAGE_SCN_LNK_INFO                      = 0x00000200 // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
	IMAGE_SECTIONFLAGS_RESERVED_400         = 0x00000400 // Reserved for future use.
	IMAGE_SCN_LNK_REMOVE                    = 0x00000800 // The section will not become part of the image. This is valid only for object files.
	IMAGE_SCN_LNK_COMDAT                    = 0x00001000 // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
	IMAGE_SCN_GPREL                         = 0x00008000 // The section contains data referenced through the global pointer (GP).
	IMAGE_SCN_MEM_PURGEABLE                 = 0x00020000 // Reserved for future use.
	IMAGE_SCN_MEM_16BIT                     = 0x00020000 // Reserved for future use.
	IMAGE_SCN_MEM_LOCKED                    = 0x00040000 // Reserved for future use.
	IMAGE_SCN_MEM_PRELOAD                   = 0x00080000 // Reserved for future use.
	IMAGE_SCN_ALIGN_1BYTES                  = 0x00100000 // Align data on a 1-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_2BYTES                  = 0x00200000 // Align data on a 2-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_4BYTES                  = 0x00300000 // Align data on a 4-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_8BYTES                  = 0x00400000 // Align data on an 8-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_16BYTES                 = 0x00500000 // Align data on a 16-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_32BYTES                 = 0x00600000 // Align data on a 32-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_64BYTES                 = 0x00700000 // Align data on a 64-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_128BYTES                = 0x00800000 // Align data on a 128-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_256BYTES                = 0x00900000 // Align data on a 256-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_512BYTES                = 0x00A00000 // Align data on a 512-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_1024BYTES               = 0x00B00000 // Align data on a 1024-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_2048BYTES               = 0x00C00000 // Align data on a 2048-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_4096BYTES               = 0x00D00000 // Align data on a 4096-byte boundary. Valid only for object files.
	IMAGE_SCN_ALIGN_8192BYTES               = 0x00E00000 // Align data on an 8192-byte boundary. Valid only for object files.
	IMAGE_SCN_LNK_NRELOC_OVFL               = 0x01000000 // The section contains extended relocations.
	IMAGE_SCN_MEM_DISCARDABLE               = 0x02000000 // The section can be discarded as needed.
	IMAGE_SCN_MEM_NOT_CACHED                = 0x04000000 // The section cannot be cached.
	IMAGE_SCN_MEM_NOT_PAGED                 = 0x08000000 // The section is not pageable.
	IMAGE_SECTIONFLAGS_MEM_SHARED           = 0x10000000 // The section can be shared in memory.
	IMAGE_SCN_MEM_EXECUTE                   = 0x20000000 // The section can be executed as code.
	IMAGE_SCN_MEM_READ                      = 0x40000000 // The section can be read.
	IMAGE_SCN_MEM_WRITE                     = 0x80000000 // The section can be written to.
)

// DataDirectories

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
)

// Section debug
const (
	IMAGE_DEBUG_TYPE_UNKNOWN               = 0  // An unknown value that is ignored by all tools.
	IMAGE_DEBUG_TYPE_COFF                  = 1  // The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
	IMAGE_DEBUG_TYPE_CODEVIEW              = 2  // The Visual C++ debug information.
	IMAGE_DEBUG_TYPE_FPO                   = 3  // The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
	IMAGE_DEBUG_TYPE_MISC                  = 4  // The location of DBG file.
	IMAGE_DEBUG_TYPE_EXCEPTION             = 5  // A copy of .pdata section.
	IMAGE_DEBUG_TYPE_FIXUP                 = 6  // Reserved.
	IMAGE_DEBUG_TYPE_OMAP_TO_SRC           = 7  // The mapping from an RVA in image to an RVA in source image.
	IMAGE_DEBUG_TYPE_OMAP_FROM_SRC         = 8  // The mapping from an RVA in source image to an RVA in image.
	IMAGE_DEBUG_TYPE_BORLAND               = 9  // Reserved for Borland.
	IMAGE_DEBUG_TYPE_RESERVED10            = 10 // Reserved.
	IMAGE_DEBUG_TYPE_CLSID                 = 11 // Reserved.
	IMAGE_DEBUG_TYPE_VC_FEATURE            = 12 // VisualC++
	IMAGE_DEBUG_TYPE_PGO                   = 13 // Profile Guided Optimization
	IMAGE_DEBUG_TYPE_REPRO                 = 16 // PE determinism or reproducibility.
	IMAGE_DEBUG_TYPE_EMBEDDED_PPDB         = 17 // Embedded Portable PDB data
	IMAGE_DEBUG_TYPE_PDB_CHECKSUM          = 19 // Checksum of PDB file
	IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20 // Extended DLL characteristics bits.
)

const (
	DEBUG_CV_SIGNATURE_RSDS = 0x53445352 // SDSR

	DEBUG_CV_SIGNATURE_NB10 = 0x3031424e // "NB10"
)

func PrintMajorOperatingSystemVersion(value uint16) string {
	switch value {
	case 10:
		return "Windows Server 2016/2019/2022 - Windows 10/ Windows 11"
	case 6:
		return "Windows Vista / Windows 7 / Windows 8"
	case 5:
		return "Windows Server 2003 - Windows 2000/XP"
	case 4:
		return "Windows 95 / Windows NT 4 / Windows 2000"
	}
	return ""
}

func PrintSubsystem(subsystem uint16) string {
	switch subsystem {
	case IMAGE_SUBSYSTEM_UNKNOWN:
		return "An unknown subsystem"
	case IMAGE_SUBSYSTEM_NATIVE:
		return "Device drivers and native Windows processes"
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "The Windows graphical user interface (GUI) subsystem"
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "The Windows character subsystem"
	case IMAGE_SUBSYSTEM_OS2_CUI:
		return "The OS/2 character subsystem"
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		return "The Posix character subsystem"
	case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		return "Native Win9x driver"
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		return "Windows CE"
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "An Extensible Firmware Interface (EFI) application"
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "An EFI driver with boot services"
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "An EFI driver with run-time services"
	case IMAGE_SUBSYSTEM_EFI_ROM:
		return "An EFI ROM image"
	case IMAGE_SUBSYSTEM_XBOX:
		return "XBOX"
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		return "Windows boot application."
	}
	return ""
}

func PrintArchitecture(machine uint16) string {
	// Stampa l'architettura contenuta nell'header COFF

	switch machine {
	case IMAGE_FILE_MACHINE_UNKNOWN:
		return "Sconosciuto"

	case IMAGE_FILE_MACHINE_AM33:
		return "Matsushita AM33"

	case IMAGE_FILE_MACHINE_AMD64:
		return "Architettura x64"

	case IMAGE_FILE_MACHINE_ARM:
		return "ARM little endian"

	case IMAGE_FILE_MACHINE_ARM64:
		return "ARM64 little endian"

	case IMAGE_FILE_MACHINE_ARMNT:
		return "ARM Thumb-2 little endian"

	case IMAGE_FILE_MACHINE_EBC:
		return "EFI byte code"

	case IMAGE_FILE_MACHINE_I386:
		return "Intel 386 or later processors and compatible processors"

	case IMAGE_FILE_MACHINE_IA64:
		return "Intel Itanium processor family"

	case IMAGE_FILE_MACHINE_LOONGARCH32:
		return "LoongArch 32-bit processor family"

	case IMAGE_FILE_MACHINE_LOONGARCH64:
		return "LoongArch 64-bit processor family"

	case IMAGE_FILE_MACHINE_M32R:
		return "Mitsubishi M32R little endian"

	case IMAGE_FILE_MACHINE_MIPS16:
		return "MIPS16"

	case IMAGE_FILE_MACHINE_MIPSFPU:
		return "MIPS with FPU"

	case IMAGE_FILE_MACHINE_MIPSFPU16:
		return "MIPS16 with FPU"

	case IMAGE_FILE_MACHINE_POWERPC:
		return "Power PC little endian"

	case IMAGE_FILE_MACHINE_POWERPCFP:
		return "Power PC with floating point support"

	case IMAGE_FILE_MACHINE_R4000:
		return "MIPS little endian"

	case IMAGE_FILE_MACHINE_RISCV32:
		return "RISC-V 32-bit address space"

	case IMAGE_FILE_MACHINE_RISCV64:
		return "RISC-V 64-bit address space"

	case IMAGE_FILE_MACHINE_RISCV128:
		return "RISC-V 128-bit address space"

	case IMAGE_FILE_MACHINE_SH3:
		return "Hitachi SH3"

	case IMAGE_FILE_MACHINE_SH3DSP:
		return "Hitachi SH3 DSP"
	case IMAGE_FILE_MACHINE_SH4:
		return "Hitachi SH4"
	case IMAGE_FILE_MACHINE_SH5:
		return "Hitachi SH5"
	case IMAGE_FILE_MACHINE_THUMB:
		return "Thumb"
	case IMAGE_FILE_MACHINE_WCEMIPSV2:
		return "MIPS little-endian WCE v2"
	}
	return ""
}

func PrintCharacteristic(constant int) string {
	switch constant {
	case IMAGE_DDLCHARACTERISTICS_RESERVED_1:
	case IMAGE_DDLCHARACTERISTICS_RESERVED_2:
	case IMAGE_DDLCHARACTERISTICS_RESERVED_4:
	case IMAGE_DDLCHARACTERISTICS_RESERVED_8:
		return "Il campo ha valori riservati."

	case IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:
		return "L'immagine può gestire un valore molto alto di entropia."

	case IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
		return "La DLL può essere riposizionata a tempo di caricamento."

	case IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY:
		return "Sono stati forzati i controlli di integrità del codice."
	case IMAGE_DLLCHARACTERISTICS_NX_COMPAT:
		// NX sta per No eXecute, tecnologia per rendere alcune aree di memoria non eseguibili
		return "L'immagine è compatibile con la tecnologia NX"
	case IMAGE_DLLCHARACTERISTICS_NO_ISOLATION:
		// https://docs.microsoft.com/en-us/cpp/build/reference/allowisolation?redirectedfrom=MSDN&view=msvc-170
		return "Isolamento disabilitato: il loader di Windows non proverà a caricare alcun manifest."

	// TODO!
	case IMAGE_DLLCHARACTERISTICS_NO_SEH:
		return "Does not use structured exception (SE) handling. No SE handler may be called in this image."
	case IMAGE_DLLCHARACTERISTICS_NO_BIND:
		return "Non esegue il binding dell'immagine"
	case IMAGE_DLLCHARACTERISTICS_APPCONTAINER:
		return "Image must execute in an AppContainer."
	case IMAGE_DLLCHARACTERISTICS_WDM_DRIVER:
		return "Driver WDM"
	case IMAGE_DLLCHARACTERISTICS_GUARD_CF:
		return "Image supports Control Flow Guard."
	case IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE:
		return "Terminal Server aware"
	}
	return ""
}

func PrintSectionFlags(flags uint32) string {
	var result []string

	if (IMAGE_SECTIONFLAGS_RESERVED_1 & flags) == IMAGE_SECTIONFLAGS_RESERVED_1 {
		result = append(result, "Reserved for future use2")
	}
	if (IMAGE_SECTIONFLAGS_RESERVED_4 & flags) == IMAGE_SECTIONFLAGS_RESERVED_4 {
		result = append(result, "Reserved for future use3")
	}
	if (IMAGE_SECTIONFLAGS_RESERVED_10 & flags) == IMAGE_SECTIONFLAGS_RESERVED_10 {
		result = append(result, "Reserved for future use4")
	}
	if (IMAGE_SECTIONFLAGS_RESERVED_400 & flags) == IMAGE_SECTIONFLAGS_RESERVED_400 {
		result = append(result, "Reserved for future use5")
	}

	if (IMAGE_SECTIONFLAGS_CNT_CODE & flags) == IMAGE_SECTIONFLAGS_CNT_CODE {
		result = append(result, "CODE")
	}

	if (IMAGE_SECTIONFLAGS_CNT_INITIALIZED_DATA & flags) == IMAGE_SECTIONFLAGS_CNT_INITIALIZED_DATA {
		result = append(result, "INITIALIZED DATA")
	}

	if (IMAGE_SCN_MEM_EXECUTE & flags) == IMAGE_SCN_MEM_EXECUTE {
		result = append(result, "EXECUTE")
	}

	if (IMAGE_SCN_MEM_READ & flags) == IMAGE_SCN_MEM_READ {
		result = append(result, "READ")
	}

	if (IMAGE_SCN_MEM_WRITE & flags) == IMAGE_SCN_MEM_WRITE {
		result = append(result, "WRITE")
	}

	return strings.Join(result, ", ")
}

func PrintResource(constant int) string {
	// Stampa la risorsa trovata

	switch constant {
	case RT_CURSOR:
		return "Cursori"
	case RT_BITMAP:
		return "Bitmap"
	case RT_ICON:
		return "Icone"
	case RT_MENU:
		return "Menu"
	case RT_DIALOG:
		return "Dialoghi"
	case RT_STRING:
		return "Stringhe"
	case RT_FONTDIR:
		return "FontDir"
	case RT_FONT:
		return "Font"
	case RT_ACCELERATORS:
		return "Accelerator"
	case RT_RCDATA:
		return "RcData"
	case RT_MESSAGETABLE:
		return "Tabella dei messaggi"
	case RT_GROUP_CURSOR:
		return "Gruppo di cursori"
	case RT_GROUP_ICON:
		return "Gruppo di icone"
	case RT_VERSION:
		return "Versione"
	case RT_INCLUDE_DIALOG:
		return "Dialogo"
	case RT_PLUG_PLAY:
		return ""
	case RT_ANT_CURSOR:
		return ""
	case RT_ANT_ICON:
		return ""
	case RT_HTML_PAGES:
		return "Pagine HTML"
	case RT_CONFIG_FILES:
		return "File di configurazione (manifest)"
	}
	return ""
}
