package payload

const(
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES  =  16
	IMAGE_DIRECTORY_ENTRY_EXPORT        =  0   // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT        =  1   // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE      =  2   // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION     =  3   // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY      =  4   // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC     =  5   // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG         =  6   // Debug Directory
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT     =  7   // (X86 usage)
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE  =  7   // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR     =  8   // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS           =  9   // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   = 10   // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  = 11   // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT           = 12   // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT  = 13   // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR= 14   // COM Runtime descriptor
	IMAGE_SIZEOF_SHORT_NAME             = 8

    IMAGE_REL_BASED_ABSOLUTE             = 0
    IMAGE_REL_BASED_HIGH                 = 1
    IMAGE_REL_BASED_LOW                  = 2
    IMAGE_REL_BASED_HIGHLOW              = 3
    IMAGE_REL_BASED_HIGHADJ              = 4
    IMAGE_REL_BASED_MACHINE_SPECIFIC_5   = 5
    IMAGE_REL_BASED_RESERVED             = 6
    IMAGE_REL_BASED_MACHINE_SPECIFIC_7   = 7
    IMAGE_REL_BASED_MACHINE_SPECIFIC_8   = 8
    IMAGE_REL_BASED_MACHINE_SPECIFIC_9   = 9
    IMAGE_REL_BASED_DIR64                = 10
    PAGE_NOACCESS       =    0x01 
    PAGE_READONLY          = 0x02 
   
    PAGE_WRITECOPY         = 0x08 
    PAGE_EXECUTE           = 0x10 
   // MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40 
    PAGE_EXECUTE_WRITECOPY = 0x80 
    IMAGE_SCN_MEM_EXECUTE           =     0x20000000
    IMAGE_SCN_MEM_READ              =     0x40000000
    IMAGE_SCN_MEM_WRITE             =     0x80000000
    
)

type  IMAGE_RUNTIME_FUNCTION_ENTRY struct{
     BeginAddress uint32;
     EndAddress  uint32;

     UnwindData uint32;
    
} 

type IMAGE_TLS_DIRECTORY struct{
     StartAddressOfRawData uintptr;
     EndAddressOfRawData uintptr;
     AddressOfIndex   uintptr;         // PDWORD
     AddressOfCallBacks uintptr;     // PIMAGE_TLS_CALLBACK *;
    SizeOfZeroFill  uint32;
    
    Characteristics uint32;
  

} 
type IMAGE_IMPORT_DESCRIPTOR struct{
   

       OriginalFirstThunk uint32;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)

       TimeDateStamp   uint32;                  // 0 if not bound,
                                       // -1 if bound, and real date\time stamp
                                       //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                       // O.W. date/time stamp of DLL bound to (Old BIND)

       ForwarderChain  uint32;                 // -1 if no forwarders
       Name    uint32;
       FirstThunk     uint32;                     // RVA to IAT (if bound this IAT has actual addresses)
} 


type IMAGE_BASE_RELOCATION struct{
     VirtualAddress uint32;
     SizeOfBlock uint32;
//  WORD    TypeOffset[1];
} 

type  IMAGE_FILE_HEADER struct{
      Machine uint16;
      NumberOfSections uint16;
      TimeDateStamp uint32;
      PointerToSymbolTable uint32;
      NumberOfSymbols uint32;
      SizeOfOptionalHeader uint16;
      Characteristics uint16;
}
type  IMAGE_DATA_DIRECTORY struct{
    VirtualAddress uint32;
    Size uint32;
}
type IMAGE_OPTIONAL_HEADER struct{
    Magic uint16;
    MajorLinkerVersion uint8;
    MinorLinkerVersion uint8;
    SizeOfCode uint32;
    SizeOfInitializedData uint32;
    SizeOfUninitializedData uint32;
    AddressOfEntryPoint uint32;
    BaseOfCode uint32;
    
    ImageBase uint64;
    SectionAlignment uint32;
    FileAlignment uint32;
    MajorOperatingSystemVersion uint16;
    MinorOperatingSystemVersion uint16;
    MajorImageVersion uint16;
    MinorImageVersion uint16;
    MajorSubsystemVersion uint16;
    MinorSubsystemVersion uint16;
    Win32VersionValue uint32;
    SizeOfImage uint32;
    SizeOfHeaders uint32;
    CheckSum uint32;
    Subsystem uint16;
    DllCharacteristics uint16;
    SizeOfStackReserve uintptr;
    SizeOfStackCommit uintptr;
    SizeOfHeapReserve uintptr;
    SizeOfHeapCommit uintptr;
    LoaderFlags uint32;
    NumberOfRvaAndSizes uint32;
    DataDirectory  [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY;
}





type IMAGE_IMPORT_BY_NAME struct {
    	Hint uint16;
       Name  [1]byte;
} 
//@[comment("MVI_tracked")]
type IMAGE_THUNK_DATA struct{
    
        AddressOfData uintptr;        // PIMAGE_IMPORT_BY_NAME
   
} 


type  IMAGE_NT_HEADERS struct{
   Signature uint32;
   FileHeader IMAGE_FILE_HEADER;
   OptionalHeader IMAGE_OPTIONAL_HEADER ;
}

type  IMAGE_SECTION_HEADER struct{
    Name [IMAGE_SIZEOF_SHORT_NAME]byte;
    VirtualSize uint32;
    VirtualAddress uint32;
    SizeOfRawData uint32;
    PointerToRawData uint32;
    PointerToRelocations uint32;
    PointerToLinenumbers uint32;
    NumberOfRelocations uint16;
    NumberOfLinenumbers uint16;
    Characteristics uint32;
} 
type  IMAGE_EXPORT_DIRECTORY struct{
     Characteristics uint32;
     TimeDateStamp uint32;
     MajorVersion uint16;
     MinorVersion uint16;
     Name uint32;
     Base uint32;
     NumberOfFunctions uint32;   
     NumberOfNames uint32; 
     AddressOfFunctions uint32;    // RVA from base of image
     AddressOfNames uint32;          // RVA from base of image
     AddressOfNameOrdinals uint32;  // RVA from base of image
} 