package elf

// Tipo di file
const (
	ET_NONE   = 0      // Nessun tipo di file specificato
	ET_REL    = 1      // File rilocabile
	ET_EXEC   = 2      // File eseguibile
	ET_DYN    = 3      // File oggetto condiviso
	ET_CORE   = 4      // File core
	ET_LOPROC = 0xff00 // Specifico del processore
	ET_HIPROC = 0xffff // Specifico del processore
)

// Machine

const (
	MACHINE_NONE          = 0   // Nessun tipo di macchina specificato
	MACHINE_M32           = 1   // M32
	MACHINE_SPARC         = 2   // Sparc
	MACHINE_X386          = 3   // Intel 80386
	MACHINE_X68K          = 4   // Intel 8068K
	MACHINE_X88K          = 5   // Intel 8088K
	MACHINE_X860          = 7   // Intel 80860
	MACHINE_MIPS          = 8   // MIPS
	MACHINE_MIPS_RS3_LE   = 10  // MIPS RS3000 Little Endian
	MACHINE_EM_PARISC     = 15  // Hewlett Packard RISC
	MACHINE_VPP500        = 17  // Fujitsu VPP500
	MACHINE_SPARC32PLUS   = 18  // Sun SPARC32+
	MACHINE_960           = 19  // Intel 80960
	MACHINE_PPC           = 20  // PowerPC
	MACHINE_PPC64         = 21  // PowerPC 64 bit
	MACHINE_S390          = 22  // IBM system
	MACHINE_SPU           = 23  // IBM SPU/SPC
	MACHINE_V800          = 36  // NEC v800
	MACHINE_RCE           = 39  // Motorola RCE
	MACHINE_ARM           = 40  // ARM 32-bit architecture (AARCH32)
	MACHINE_ALPHA         = 41  // Digital Alpha
	MACHINE_SH            = 42  // Hitachi SH
	MACHINE_SPARCV9       = 43  // SPARC Version 9
	MACHINE_TRICORE       = 44  // Siemens TriCore embedded processor
	MACHINE_ARC           = 45  // Argonaut RISC Core, Argonaut Technologies Inc.
	MACHINE_H8_300        = 46  // Hitachi H8/300
	MACHINE_H8_300H       = 47  // Hitachi H8/300H
	MACHINE_H8S           = 48  // Hitachi H8S
	MACHINE_H8_500        = 49  // Hitachi H8/500
	MACHINE_IA_64         = 50  // Intel IA-64 processor architecture
	MACHINE_MIPS_X        = 51  // Stanford MIPS-X
	MACHINE_COLDFIRE      = 52  // Motorola ColdFire
	MACHINE_68HC12        = 53  // Motorola M68HC12
	MACHINE_MMA           = 54  // Fujitsu MMA Multimedia Accelerator
	MACHINE_PCP           = 55  // Siemens PCP
	MACHINE_NCPU          = 56  // Sony nCPU embedded RISC processor
	MACHINE_NDR1          = 57  // Denso NDR1 microprocessor
	MACHINE_STARCORE      = 58  // Motorola Star*Core processor
	MACHINE_ME16          = 59  // Toyota ME16 processor
	MACHINE_ST100         = 60  // STMicroelectronics ST100 processor
	MACHINE_TINYJ         = 61  // Advanced Logic Corp. TinyJ embedded processor family
	MACHINE_X86_64        = 62  // AMD x86-64 architecture
	MACHINE_PDSP          = 63  // Sony DSP Processor
	MACHINE_PDP10         = 64  // Digital Equipment Corp. PDP-10
	MACHINE_PDP11         = 65  // Digital Equipment Corp. PDP-11
	MACHINE_FX66          = 66  // Siemens FX66 microcontroller
	MACHINE_ST9PLUS       = 67  // STMicroelectronics ST9+ 8/16 bit microcontroller
	MACHINE_ST7           = 68  // STMicroelectronics ST7 8-bit microcontroller
	MACHINE_68HC16        = 69  // Motorola MC68HC16 Microcontroller
	MACHINE_68HC11        = 70  // Motorola MC68HC11 Microcontroller
	MACHINE_68HC08        = 71  // Motorola MC68HC08 Microcontroller
	MACHINE_68HC05        = 72  // Motorola MC68HC05 Microcontroller
	MACHINE_SVX           = 73  // Silicon Graphics SVx
	MACHINE_ST19          = 74  // STMicroelectronics ST19 8-bit microcontroller
	MACHINE_VAX           = 75  // Digital VAX
	MACHINE_CRIS          = 76  // Axis Communications 32-bit embedded processor
	MACHINE_JAVELIN       = 77  // Infineon Technologies 32-bit embedded processor
	MACHINE_FIREPATH      = 78  // Element 14 64-bit DSP Processor
	MACHINE_ZSP           = 79  // LSI Logic 16-bit DSP Processor
	MACHINE_MMIX          = 80  // Donald Knuth's educational 64-bit processor
	MACHINE_HUANY         = 81  // Harvard University machine-independent object files
	MACHINE_PRISM         = 82  // SiTera Prism
	MACHINE_AVR           = 83  // Atmel AVR 8-bit microcontroller
	MACHINE_FR30          = 84  // Fujitsu FR30
	MACHINE_D10V          = 85  // Mitsubishi D10V
	MACHINE_D30V          = 86  // Mitsubishi D30V
	MACHINE_V850          = 87  // NEC v850
	MACHINE_M32R          = 88  // Mitsubishi M32R
	MACHINE_MN10300       = 89  // Matsushita MN10300
	MACHINE_MN10200       = 90  // Matsushita MN10200
	MACHINE_PJ            = 91  // picoJava
	MACHINE_OPENRISC      = 92  // OpenRISC 32-bit embedded processor
	MACHINE_ARC_COMPACT   = 93  // ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
	MACHINE_XTENSA        = 94  // Tensilica Xtensa Architecture
	MACHINE_VIDEOCORE     = 95  // Alphamosaic VideoCore processor
	MACHINE_TMM_GPP       = 96  // Thompson Multimedia General Purpose Processor
	MACHINE_NS32K         = 97  // National Semiconductor 32000 series
	MACHINE_TPC           = 98  // Tenor Network TPC processor
	MACHINE_SNP1K         = 99  // Trebia SNP 1000 processor
	MACHINE_ST200         = 100 // STMicroelectronics (www.st.com) ST200 microcontroller
	MACHINE_IP2K          = 101 // Ubicom IP2xxx microcontroller family
	MACHINE_MAX           = 102 // MAX Processor
	MACHINE_CR            = 103 // National Semiconductor CompactRISC microprocessor
	MACHINE_F2MC16        = 104 // Fujitsu F2MC16
	MACHINE_MSP430        = 105 // Texas Instruments embedded microcontroller msp430
	MACHINE_BLACKFIN      = 106 // Analog Devices Blackfin (DSP) processor
	MACHINE_SE_C33        = 107 // S1C33 Family of Seiko Epson processors
	MACHINE_SEP           = 108 // Sharp embedded microprocessor
	MACHINE_ARCA          = 109 // Arca RISC Microprocessor
	MACHINE_UNICORE       = 110 // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
	MACHINE_EXCESS        = 111 // eXcess: 16/32/64-bit configurable embedded CPU
	MACHINE_DXP           = 112 // Icera Semiconductor Inc. Deep Execution Processor
	MACHINE_ALTERA_NIOS2  = 113 // Altera Nios II soft-core processor
	MACHINE_CRX           = 114 // National Semiconductor CompactRISC CRX microprocessor
	MACHINE_XGATE         = 115 // Motorola XGATE embedded processor
	MACHINE_C166          = 116 // Infineon C16x/XC16x processor
	MACHINE_M16C          = 117 // Renesas M16C series microprocessors
	MACHINE_DSPIC30F      = 118 // Microchip Technology dsPIC30F Digital Signal Controller
	MACHINE_CE            = 119 // Freescale Communication Engine RISC core
	MACHINE_M32C          = 120 // Renesas M32C series microprocessors
	MACHINE_TSK3000       = 131 // Altium TSK3000 core
	MACHINE_RS08          = 132 // Freescale RS08 embedded processor
	MACHINE_SHARC         = 133 // Analog Devices SHARC family of 32-bit DSP processors
	MACHINE_ECOG2         = 134 // Cyan Technology eCOG2 microprocessor
	MACHINE_SCORE7        = 135 // Sunplus S+core7 RISC processor
	MACHINE_DSP24         = 136 // New Japan Radio (NJR) 24-bit DSP Processor
	MACHINE_VIDEOCORE3    = 137 // Broadcom VideoCore III processor
	MACHINE_LATTICEMICO32 = 138 // RISC processor for Lattice FPGA architecture
	MACHINE_SE_C17        = 139 // Seiko Epson C17 family
	MACHINE_TI_C6000      = 140 // The Texas Instruments TMS320C6000 DSP family
	MACHINE_TI_C2000      = 141 // The Texas Instruments TMS320C2000 DSP family
	MACHINE_TI_C5500      = 142 // The Texas Instruments TMS320C55x DSP family
	MACHINE_TI_ARP32      = 143 // Texas Instruments Application Specific RISC Processor, 32bit fetch
	MACHINE_TI_PRU        = 144 // Texas Instruments Programmable Realtime Unit
	MACHINE_MMDSP_PLUS    = 160 // STMicroelectronics 64bit VLIW Data Signal Processor
	MACHINE_CYPRESS_M8C   = 161 // Cypress M8C microprocessor
	MACHINE_R32C          = 162 // Renesas R32C series microprocessors
	MACHINE_TRIMEDIA      = 163 // NXP Semiconductors TriMedia architecture family
	MACHINE_QDSP6         = 164 // QUALCOMM DSP6 Processor
	MACHINE_8051          = 165 // Intel 8051 and variants
	MACHINE_STXP7X        = 166 // STMicroelectronics STxP7x family of configurable and extensible RISC processors
	MACHINE_NDS32         = 167 // Andes Technology compact code size embedded RISC processor family
	MACHINE_ECOG1         = 168 // Cyan Technology eCOG1X family
	MACHINE_ECOG1X        = 168 // Cyan Technology eCOG1X family
	MACHINE_MAXQ30        = 169 // Dallas Semiconductor MAXQ30 Core Micro-controllers
	MACHINE_XIMO16        = 170 // New Japan Radio (NJR) 16-bit DSP Processor
	MACHINE_MANIK         = 171 // M2000 Reconfigurable RISC Microprocessor
	MACHINE_CRAYNV2       = 172 // Cray Inc. NV2 vector architecture
	MACHINE_RX            = 173 // Renesas RX family
	MACHINE_METAG         = 174 // Imagination Technologies META processor architecture
	MACHINE_MCST_ELBRUS   = 175 // MCST Elbrus general purpose hardware architecture
	MACHINE_ECOG16        = 176 // Cyan Technology eCOG16 family
	MACHINE_CR16          = 177 // National Semiconductor CompactRISC CR16 16-bit microprocessor
	MACHINE_ETPU          = 178 // Freescale Extended Time Processing Unit
	MACHINE_SLE9X         = 179 // Infineon Technologies SLE9X core
	MACHINE_L10M          = 180 // Intel L10M
	MACHINE_K10M          = 181 // Intel K10M
	MACHINE_AARCH64       = 183 // ARM 64-bit architecture (AARCH64)
	MACHINE_AVR32         = 185 // Atmel Corporation 32-bit microprocessor family
	MACHINE_STM8          = 186 // STMicroeletronics STM8 8-bit microcontroller
	MACHINE_TILE64        = 187 // Tilera TILE64 multicore architecture family
	MACHINE_TILEPRO       = 188 // Tilera TILEPro multicore architecture family
	MACHINE_MICROBLAZE    = 189 // Xilinx MicroBlaze 32-bit RISC soft processor core
	MACHINE_CUDA          = 190 // NVIDIA CUDA architecture
	MACHINE_TILEGX        = 191 // Tilera TILE-Gx multicore architecture family
	MACHINE_CLOUDSHIELD   = 192 // CloudShield architecture family
	MACHINE_COREA_1ST     = 193 // KIPO-KAIST Core-A 1st generation processor family
	MACHINE_COREA_2ND     = 194 // KIPO-KAIST Core-A 2nd generation processor family
	MACHINE_ARC_COMPACT2  = 195 // Synopsys ARCompact V2
	MACHINE_OPEN8         = 196 // Open8 8-bit RISC soft processor core
	MACHINE_RL78          = 197 // Renesas RL78 family
	MACHINE_VIDEOCORE5    = 198 // Broadcom VideoCore V processor
	MACHINE_78KOR         = 199 // Renesas 78KOR family
	MACHINE_56800EX       = 200 // Freescale 56800EX Digital Signal Controller (DSC)
	MACHINE_BA1           = 201 // Beyond BA1 CPU architecture
	MACHINE_BA2           = 202 // Beyond BA2 CPU architecture
	MACHINE_XCORE         = 203 // XMOS xCORE processor family
	MACHINE_MCHP_PIC      = 204 // Microchip 8-bit PIC(r) family
	MACHINE_INTEL205      = 205 // Reserved by Intel
	MACHINE_INTEL206      = 206 // Reserved by Intel
	MACHINE_INTEL207      = 207 // Reserved by Intel
	MACHINE_INTEL208      = 208 // Reserved by Intel
	MACHINE_INTEL209      = 209 // Reserved by Intel
	MACHINE_KM32          = 210 // KM211 KM32 32-bit processor
	MACHINE_KMX32         = 211 // KM211 KMX32 32-bit processor
	MACHINE_KMX16         = 212 // KM211 KMX16 16-bit processor
	MACHINE_KMX8          = 213 // KM211 KMX8 8-bit processor
	MACHINE_KVARC         = 214 // KM211 KVARC processor
	MACHINE_CDP           = 215 // Paneve CDP architecture family
	MACHINE_COGE          = 216 // Cognitive Smart Memory Processor
	MACHINE_COOL          = 217 // Bluechip Systems CoolEngine
	MACHINE_NORC          = 218 // Nanoradio Optimized RISC
	MACHINE_CSR_KALIMBA   = 219 // CSR Kalimba architecture family
	MACHINE_Z80           = 220 // Zilog Z80
	MACHINE_VISIUM        = 221 // Controls and Data Services VISIUMcore processor
	MACHINE_FT32          = 222 // FTDI Chip FT32 high performance 32-bit RISC architecture
	MACHINE_MOXIE         = 223 // Moxie processor family
	MACHINE_AMDGPU        = 224 // AMD GPU architecture
	MACHINE_RISCV         = 243 // RISC-V
)

// Versione ELF
const (
	VERSION_NONE    = 0 // Versione invalida
	VERSION_CURRENT = 1 // Versione corrente
)

const (
	ARCHITECTURE_32 = 1 // 32 bit
	ARCHITECTURE_64 = 2 // 64 bit
)

// OSABI (Application Binary Interface)
const (
	OSABI_SYSTEM_V   = 0  // SystemV
	OSABI_HPUX       = 1  // HP UX
	OSABI_NETBSD     = 2  // NetBSD
	OSABI_LINUX      = 3  // GNU/Linux
	OSABI_HURD       = 4  // Gnu/Hurd
	OSABI_86OPEN     = 5  // 86Open common IA32 ABI
	OSABI_SOLARIS    = 6  // Solaris
	OSABI_AIX        = 7  // AIX
	OSABI_IRIX       = 8  // IRIX
	OSABI_FREEBSD    = 9  // FreeBSD
	OSABI_TRU64      = 10 // TRU64 UNIX
	OSABI_MODESTO    = 11 // Novell Modesto
	OSABI_OPENBSD    = 12 // OpenBSD
	OSABI_OPENVMS    = 13 // Open VMS
	OSABI_NSK        = 14 // HP Non-Stop Kernel
	OSABI_AROS       = 15 // Amiga Research OS
	OSABI_FENIXOS    = 16 // The FenixOS highly scalable multi-core OS
	OSABI_CLOUDABI   = 17 // Nuxi CloudABI
	OSABI_ARM        = 97 // ARM
	OSABI_STANDALONE = 255
)

const (
	SHT_NULL           = 0          // inactive
	SHT_PROGBITS       = 1          // program defined information
	SHT_SYMTAB         = 2          // symbol table section
	SHT_STRTAB         = 3          // string table section
	SHT_RELA           = 4          // relocation section with addends
	SHT_HASH           = 5          // symbol hash table section
	SHT_DYNAMIC        = 6          // dynamic section
	SHT_NOTE           = 7          // note section
	SHT_NOBITS         = 8          // no space section
	SHT_REL            = 9          // relocation section - no addends
	SHT_SHLIB          = 10         // reserved - purpose unknown
	SHT_DYNSYM         = 11         // dynamic symbol table section
	SHT_INIT_ARRAY     = 14         // Initialization function pointers.
	SHT_FINI_ARRAY     = 15         // Termination function pointers.
	SHT_PREINIT_ARRAY  = 16         // Pre-initialization function ptrs.
	SHT_GROUP          = 17         // Section group.
	SHT_SYMTAB_SHNDX   = 18         // Section indexes (see SHN_XINDEX).
	SHT_LOOS           = 0x60000000 // First of OS specific semantics
	SHT_GNU_ATTRIBUTES = 0x6ffffff5 // GNU object attributes
	SHT_GNU_HASH       = 0x6ffffff6 // GNU hash table
	SHT_GNU_LIBLIST    = 0x6ffffff7 // GNU prelink library list
	SHT_GNU_VERDEF     = 0x6ffffffd // GNU version definition section
	SHT_GNU_VERNEED    = 0x6ffffffe // GNU version needs section
	SHT_GNU_VERSYM     = 0x6fffffff // GNU version symbol table
	SHT_HIOS           = 0x6fffffff // Last of OS specific semantics
	SHT_LOPROC         = 0x70000000 // reserved range for processor
	SHT_HIPROC         = 0x7fffffff // specific section header types
	SHT_LOUSER         = 0x80000000 // reserved range for application
	SHT_HIUSER         = 0xffffffff // specific indexes
)

func PrintFileType(t uint16) string {
	switch t {
	case ET_NONE:
		return "Nessun tipo di file specificato"
	case ET_REL:
		return "File rilocabile"
	case ET_EXEC:
		return "File eseguibile"
	case ET_DYN:
		return "File oggetto condiviso"
	case ET_CORE:
		return "File core"
	}
	return ""
}

func PrintMachine(machine uint16) string {
	switch machine {
	case MACHINE_NONE:
		return "Nessun tipo di macchina specificato"
	case MACHINE_M32:
		return "M32"
	case MACHINE_SPARC:
		return "Sparc"
	case MACHINE_X386:
		return "Intel 80386"
	case MACHINE_X68K:
		return "Intel 8068K"
	case MACHINE_X88K:
		return "Intel 8088K"
	case MACHINE_X860:
		return "Intel 80860"
	case MACHINE_MIPS:
		return "MIPS"
	case MACHINE_MIPS_RS3_LE:
		return "MIPS RS3000 Little Endian"
	case MACHINE_EM_PARISC:
		return "Hewlett Packard RISC"
	case MACHINE_VPP500:
		return "Fujitsu VPP500"
	case MACHINE_SPARC32PLUS:
		return "Sun SPARC32+"
	case MACHINE_960:
		return "Intel 80960"
	case MACHINE_PPC:
		return "PowerPC"
	case MACHINE_PPC64:
		return "PowerPC 64 bit"
	case MACHINE_S390:
		return "IBM system"
	case MACHINE_SPU:
		return "IBM SPU/SPC"
	case MACHINE_V800:
		return "NEC v800"
	case MACHINE_RCE:
		return "Motorola RCE"
	case MACHINE_ARM:
		return "ARM 32-bit architecture (AARCH32)"
	case MACHINE_ALPHA:
		return "Digital Alpha"
	case MACHINE_SH:
		return "Hitachi SH"
	case MACHINE_SPARCV9:
		return "SPARC Version 9"
	case MACHINE_TRICORE:
		return "Siemens TriCore embedded processor"
	case MACHINE_ARC:
		return "Argonaut RISC Core, Argonaut Technologies Inc."
	case MACHINE_H8_300:
		return "Hitachi H8/300"
	case MACHINE_H8_300H:
		return "Hitachi H8/300H"
	case MACHINE_H8S:
		return "Hitachi H8S"
	case MACHINE_H8_500:
		return "Hitachi H8/500"
	case MACHINE_IA_64:
		return "Intel IA-64 processor architecture"
	case MACHINE_MIPS_X:
		return "Stanford MIPS-X"
	case MACHINE_COLDFIRE:
		return "Motorola ColdFire"
	case MACHINE_68HC12:
		return "Motorola M68HC12"
	case MACHINE_MMA:
		return "Fujitsu MMA Multimedia Accelerator"
	case MACHINE_PCP:
		return "Siemens PCP"
	case MACHINE_NCPU:
		return "Sony nCPU embedded RISC processor"
	case MACHINE_NDR1:
		return "Denso NDR1 microprocessor"
	case MACHINE_STARCORE:
		return "Motorola Star*Core processor"
	case MACHINE_ME16:
		return "Toyota ME16 processor"
	case MACHINE_ST100:
		return "STMicroelectronics ST100 processor"
	case MACHINE_TINYJ:
		return "Advanced Logic Corp. TinyJ embedded processor family"
	case MACHINE_X86_64:
		return "AMD x86-64 architecture"
	case MACHINE_PDSP:
		return "Sony DSP Processor"
	case MACHINE_PDP10:
		return "Digital Equipment Corp. PDP-10"
	case MACHINE_PDP11:
		return "Digital Equipment Corp. PDP-11"
	case MACHINE_FX66:
		return "Siemens FX66 microcontroller"
	case MACHINE_ST9PLUS:
		return "STMicroelectronics ST9+ 8/16 bit microcontroller"
	case MACHINE_ST7:
		return "STMicroelectronics ST7 8-bit microcontroller"
	case MACHINE_68HC16:
		return "Motorola MC68HC16 Microcontroller"
	case MACHINE_68HC11:
		return "Motorola MC68HC11 Microcontroller"
	case MACHINE_68HC08:
		return "Motorola MC68HC08 Microcontroller"
	case MACHINE_68HC05:
		return "Motorola MC68HC05 Microcontroller"
	case MACHINE_SVX:
		return "Silicon Graphics SVx"
	case MACHINE_ST19:
		return "STMicroelectronics ST19 8-bit microcontroller"
	case MACHINE_VAX:
		return "Digital VAX"
	case MACHINE_CRIS:
		return "Axis Communications 32-bit embedded processor"
	case MACHINE_JAVELIN:
		return "Infineon Technologies 32-bit embedded processor"
	case MACHINE_FIREPATH:
		return "Element 14 64-bit DSP Processor"
	case MACHINE_ZSP:
		return "LSI Logic 16-bit DSP Processor"
	case MACHINE_MMIX:
		return "Donald Knuth's educational 64-bit processor"
	case MACHINE_HUANY:
		return "Harvard University machine-independent object files"
	case MACHINE_PRISM:
		return "SiTera Prism"
	case MACHINE_AVR:
		return "Atmel AVR 8-bit microcontroller"
	case MACHINE_FR30:
		return "Fujitsu FR30"
	case MACHINE_D10V:
		return "Mitsubishi D10V"
	case MACHINE_D30V:
		return "Mitsubishi D30V"
	case MACHINE_V850:
		return "NEC v850"
	case MACHINE_M32R:
		return "Mitsubishi M32R"
	case MACHINE_MN10300:
		return "Matsushita MN10300"
	case MACHINE_MN10200:
		return "Matsushita MN10200"
	case MACHINE_PJ:
		return "picoJava"
	case MACHINE_OPENRISC:
		return "OpenRISC 32-bit embedded processor"
	case MACHINE_ARC_COMPACT:
		return "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)"
	case MACHINE_XTENSA:
		return "Tensilica Xtensa Architecture"
	case MACHINE_VIDEOCORE:
		return "Alphamosaic VideoCore processor"
	case MACHINE_TMM_GPP:
		return "Thompson Multimedia General Purpose Processor"
	case MACHINE_NS32K:
		return "National Semiconductor 32000 series"
	case MACHINE_TPC:
		return "Tenor Network TPC processor"
	case MACHINE_SNP1K:
		return "Trebia SNP 1000 processor"
	case MACHINE_ST200:
		return "STMicroelectronics (www.st.com) ST200 microcontroller"
	case MACHINE_IP2K:
		return "Ubicom IP2xxx microcontroller family"
	case MACHINE_MAX:
		return "MAX Processor"
	case MACHINE_CR:
		return "National Semiconductor CompactRISC microprocessor"
	case MACHINE_F2MC16:
		return "Fujitsu F2MC16"
	case MACHINE_MSP430:
		return "Texas Instruments embedded microcontroller msp430"
	case MACHINE_BLACKFIN:
		return "Analog Devices Blackfin (DSP) processor"
	case MACHINE_SE_C33:
		return "S1C33 Family of Seiko Epson processors"
	case MACHINE_SEP:
		return "Sharp embedded microprocessor"
	case MACHINE_ARCA:
		return "Arca RISC Microprocessor"
	case MACHINE_UNICORE:
		return "Microprocessor series from PKU-Unity Ltd."
	case MACHINE_EXCESS:
		return "eXcess: 16/32/64-bit configurable embedded CPU"
	case MACHINE_DXP:
		return "Icera Semiconductor Inc. Deep Execution Processor"
	case MACHINE_ALTERA_NIOS2:
		return "Altera Nios II soft-core processor"
	case MACHINE_CRX:
		return "National Semiconductor CompactRISC CRX microprocessor"
	case MACHINE_XGATE:
		return "Motorola XGATE embedded processor"
	case MACHINE_C166:
		return "Infineon C16x/XC16x processor"
	case MACHINE_M16C:
		return "Renesas M16C series microprocessors"
	case MACHINE_DSPIC30F:
		return "Microchip Technology dsPIC30F Digital Signal Controller"
	case MACHINE_CE:
		return "Freescale Communication Engine RISC core"
	case MACHINE_M32C:
		return "Renesas M32C series microprocessors"
	case MACHINE_TSK3000:
		return "Altium TSK3000 core"
	case MACHINE_RS08:
		return "Freescale RS08 embedded processor"
	case MACHINE_SHARC:
		return "Analog Devices SHARC family of 32-bit DSP processors"
	case MACHINE_ECOG2:
		return "Cyan Technology eCOG2 microprocessor"
	case MACHINE_SCORE7:
		return "Sunplus S+core7 RISC processor"
	case MACHINE_DSP24:
		return "New Japan Radio (NJR) 24-bit DSP Processor"
	case MACHINE_VIDEOCORE3:
		return "Broadcom VideoCore III processor"
	case MACHINE_LATTICEMICO32:
		return "RISC processor for Lattice FPGA architecture"
	case MACHINE_SE_C17:
		return "Seiko Epson C17 family"
	case MACHINE_TI_C6000:
		return "The Texas Instruments TMS320C6000 DSP family"
	case MACHINE_TI_C2000:
		return "The Texas Instruments TMS320C2000 DSP family"
	case MACHINE_TI_C5500:
		return "The Texas Instruments TMS320C55x DSP family"
	case MACHINE_TI_ARP32:
		return "Texas Instruments Application Specific RISC Processor, 32bit fetch"
	case MACHINE_TI_PRU:
		return "Texas Instruments Programmable Realtime Unit"
	case MACHINE_MMDSP_PLUS:
		return "STMicroelectronics 64bit VLIW Data Signal Processor"
	case MACHINE_CYPRESS_M8C:
		return "Cypress M8C microprocessor"
	case MACHINE_R32C:
		return "Renesas R32C series microprocessors"
	case MACHINE_TRIMEDIA:
		return "NXP Semiconductors TriMedia architecture family"
	case MACHINE_QDSP6:
		return "QUALCOMM DSP6 Processor"
	case MACHINE_8051:
		return "Intel 8051 and variants"
	case MACHINE_STXP7X:
		return "STMicroelectronics STxP7x family of configurable and extensible RISC processors"
	case MACHINE_NDS32:
		return "Andes Technology compact code size embedded RISC processor family"
	case MACHINE_CR16:
		return "National Semiconductor CompactRISC 16-bit microprocessor"
	case MACHINE_ECOG1:
		return "Cyan Technology eCOG1X family"
	case MACHINE_MAXQ30:
		return "Dallas Semiconductor MAXQ30 Core Micro-controllers"
	case MACHINE_XIMO16:
		return "New Japan Radio (NJR) 16-bit DSP Processor"
	case MACHINE_MANIK:
		return "M2000 Reconfigurable RISC Microprocessor"
	case MACHINE_CRAYNV2:
		return "Cray Inc. NV2 vector architecture"
	case MACHINE_RX:
		return "Renesas RX family"
	case MACHINE_METAG:
		return "Imagination Technologies META processor architecture"
	case MACHINE_MCST_ELBRUS:
		return "MCST Elbrus general purpose hardware architecture"
	case MACHINE_ECOG16:
		return "Cyan Technology eCOG16 family"
	case MACHINE_ETPU:
		return "Freescale Extended Time Processing Unit"
	case MACHINE_SLE9X:
		return "Infineon Technologies SLE9X core"
	case MACHINE_L10M:
		return "Intel L10M"
	case MACHINE_K10M:
		return "Intel K10M"
	case MACHINE_AARCH64:
		return "ARM 64-bit architecture (AARCH64)"
	case MACHINE_AVR32:
		return "Atmel Corporation 32-bit microprocessor family"
	case MACHINE_STM8:
		return "STMicroeletronics STM8 8-bit microcontroller"
	case MACHINE_TILE64:
		return "Tilera TILE64 multicore architecture family"
	case MACHINE_TILEPRO:
		return "Tilera TILEPro multicore architecture family"
	case MACHINE_MICROBLAZE:
		return "Xilinx MicroBlaze 32-bit RISC soft processor core"
	case MACHINE_CUDA:
		return "NVIDIA CUDA architecture"
	case MACHINE_TILEGX:
		return "Tilera TILE-Gx multicore architecture family"
	case MACHINE_CLOUDSHIELD:
		return "CloudShield architecture family"
	case MACHINE_COREA_1ST:
		return "KIPO-KAIST Core-A 1st generation processor family"
	case MACHINE_COREA_2ND:
		return "KIPO-KAIST Core-A 2nd generation processor family"
	case MACHINE_ARC_COMPACT2:
		return "Synopsys ARCompact V2"
	case MACHINE_OPEN8:
		return "Open8 8-bit RISC soft processor core"
	case MACHINE_RL78:
		return "Renesas RL78 family"
	case MACHINE_VIDEOCORE5:
		return "Broadcom VideoCore V processor"
	case MACHINE_78KOR:
		return "Renesas 78KOR family"
	case MACHINE_56800EX:
		return "Freescale 56800EX Digital Signal Controller (DSC)"
	case MACHINE_BA1:
		return "Beyond BA1 CPU architecture"
	case MACHINE_BA2:
		return "Beyond BA2 CPU architecture"
	case MACHINE_XCORE:
		return "XMOS xCORE processor family"
	case MACHINE_MCHP_PIC:
		return "Microchip 8-bit PIC(r) family"
	case MACHINE_INTEL205:
		return "Reserved by Intel"

	case MACHINE_INTEL206:
		return "Reserved by Intel"
	case MACHINE_INTEL207:
		return "Reserved by Intel"
	case MACHINE_INTEL208:
		return "Reserved by Intel"
	case MACHINE_INTEL209:
		return "Reserved by Intel"
	case MACHINE_KM32:
		return "KM211 KM32 32-bit processor"
	case MACHINE_KMX32:
		return "KM211 KMX32 32-bit processor"
	case MACHINE_KMX16:
		return "KM211 KMX16 16-bit processor"
	case MACHINE_KMX8:
		return "KM211 KMX8 8-bit processor"
	case MACHINE_KVARC:
		return "KM211 KVARC processor"
	case MACHINE_CDP:
		return "Paneve CDP architecture family"
	case MACHINE_COGE:
		return "Cognitive Smart Memory Processor"
	case MACHINE_COOL:
		return "Bluechip Systems CoolEngine"
	case MACHINE_NORC:
		return "Nanoradio Optimized RISC"
	case MACHINE_CSR_KALIMBA:
		return "CSR Kalimba architecture family"
	case MACHINE_Z80:
		return "Zilog Z80"
	case MACHINE_VISIUM:
		return "Controls and Data Services VISIUMcore processor"
	case MACHINE_FT32:
		return "FTDI Chip FT32 high performance 32-bit RISC architecture"
	case MACHINE_MOXIE:
		return "Moxie processor family"
	case MACHINE_AMDGPU:
		return "AMD GPU architecture"
	case MACHINE_RISCV:
		return "RISC-V"
	}
	return ""
}

func PrintSectionType(typeN uint32) string {
	switch typeN {
	case SHT_NULL:
		return "inactive"
	case SHT_PROGBITS:
		return "program defined information"
	case SHT_SYMTAB:
		return "symbol table section"
	case SHT_STRTAB:
		return "string table section"
	case SHT_RELA:
		return "relocation section with addends"
	case SHT_HASH:
		return "symbol hash table section"
	case SHT_DYNAMIC:
		return "dynamic section"
	case SHT_NOTE:
		return "note section"
	case SHT_NOBITS:
		return "no space section"
	case SHT_REL:
		return "relocation section - no addends"
	case SHT_SHLIB:
		return "reserved - purpose unknown"
	case SHT_DYNSYM:
		return "dynamic symbol table section"
	case SHT_INIT_ARRAY:
		return "Initialization function pointers."
	case SHT_FINI_ARRAY:
		return "Termination function pointers."
	case SHT_PREINIT_ARRAY:
		return "Pre-initialization function ptrs."
	case SHT_GROUP:
		return "Section group."
	case SHT_SYMTAB_SHNDX:
		return "Section indexes (see SHN_XINDEX)."
	case SHT_LOOS:
		return "First of OS specific semantics"
	case SHT_GNU_ATTRIBUTES:
		return "GNU object attributes"
	case SHT_GNU_HASH:
		return "GNU hash table"
	case SHT_GNU_LIBLIST:
		return "GNU prelink library list"
	case SHT_GNU_VERDEF:
		return "GNU version definition section"
	case SHT_GNU_VERNEED:
		return "GNU version needs section"
	case SHT_GNU_VERSYM:
		return "GNU version symbol table / Last of OS specific semantics"
	case SHT_LOPROC:
		return "reserved range for processor"
	case SHT_HIPROC:
		return "specific section header types"
	case SHT_LOUSER:
		return "reserved range for application"
	case SHT_HIUSER:
		return "specific indexes"

	}
	return ""
}
