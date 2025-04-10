package payload


import(
	"unsafe"
	"errors"
	"math/rand"
)
type SectionInfo struct{
	Memstart uint32
	Memsize  uint32
	Filestart uint32
	Filesize uint32
	Characteristics uint32
}

type FileHeaderInfo struct{
	//nSectionsOffset uint32
	NSections uint16
	
	ImportTableOffset uint32
	ImportTableSize uint32

	ReloadTableOffset uint32
	ReloadTableSize uint32

	ExportTableOffset uint32
	ExportTableSize uint32

	ExceptTableOffset uint32
	ExceptTableSize uint32

	TlsTableOffset uint32
	TlsTableSize uint32

	CodeEntryOffset uint32
	ImageBase uintptr
	HeaderSize uint32
	ImageSize uint32

	Sections []SectionInfo
}


type File struct{
	Base *Ptr
	FileHeaderInfo
	File []byte
}

func(r *File)ParseHeader(){
	filePtr:=&Ptr{Base:unsafe.Pointer(&r.File[0])}
	r.Base=filePtr
	offset:=*(filePtr.ToUint32Ptr(0x3c).Get(0))
	ntheader:=filePtr.ToIMAGE_NT_HEADERS_Ptr(offset).Get(0)
	r.NSections=ntheader.FileHeader.NumberOfSections
	r.CodeEntryOffset =ntheader.OptionalHeader.AddressOfEntryPoint;
	if unsafe.Sizeof(r.ImageBase)==4{
		r.ImageBase=uintptr(ntheader.OptionalHeader.ImageBase>>32)
	}else{
		r.ImageBase=uintptr(ntheader.OptionalHeader.ImageBase)
	}
	
	
	r.HeaderSize=ntheader.OptionalHeader.SizeOfHeaders
	r.ImageSize=ntheader.OptionalHeader.SizeOfImage
	
	

	
	imtTabEntry:=ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	r.ImportTableOffset=imtTabEntry.VirtualAddress
	r.ImportTableSize=imtTabEntry.Size

	relTabEntry:=ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	r.ReloadTableOffset=relTabEntry.VirtualAddress
	r.ReloadTableSize=relTabEntry.Size
	
	expTabEntry:=ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] ;
	r.ExportTableOffset=expTabEntry.VirtualAddress;
	r.ExportTableSize=expTabEntry.Size

	expcTabEntry:=ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] ;
	r.ExceptTableOffset=expcTabEntry.VirtualAddress;
	r.ExceptTableSize=expcTabEntry.Size

	tlsTabEntry:=ntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS ] ;
	r.TlsTableOffset=tlsTabEntry.VirtualAddress;
	r.TlsTableSize=tlsTabEntry.Size

	
	pSections:=filePtr.ToIMAGE_SECTION_HEADER_Ptr(offset+uint32(unsafe.Sizeof(*ntheader)))
	var i uint32=0
	for ;i<uint32(r.NSections);i++{
		var s SectionInfo
		p:=pSections.Get(i)
		s.Memstart=p.VirtualAddress;
		s.Memsize=p.VirtualSize;
		s.Filestart=p.PointerToRawData;
		s.Filesize=p.SizeOfRawData ;
		s.Characteristics=p.Characteristics
		r.Sections=append(r.Sections,s);
	}
}
func (f *File)RVAToFVA(r uint32)uint32{
	for i:=0;i<len(f.Sections);i++{
		if r>=f.Sections[i].Memstart && r<=f.Sections[i].Memsize+f.Sections[i].Memstart{
			return f.Sections[i].Filestart+r-f.Sections[i].Memstart
		}
	}
	return 0
}
func WriteByteSlice(bytes []byte,des *byte){
	ptr:=&BytePtr{Base:des}
	bytes=bytes[:len(bytes)-1]
	for index,item:=range bytes{
		*ptr.Get(index)=item;
	}
	
	
	
}

func ImportEncrypt(bytes []byte){
	bytes=bytes[:len(bytes)-1]
	for index:=range bytes{
		bytes[index]=bytes[index]^0x96
	}

}
func ImportDecrypt(bytes []byte){
	bytes=bytes[:len(bytes)-1]
	for index:=range bytes{
		bytes[index]=bytes[index]^0x96
	}

}

func (r *File) ConfuseHeader(){
	n:=r.Sections[0].Filestart;
	var i uint32=0;
	for ;i<n;i++{ //uint8(rand.Int());
		r.File[i]=uint8(rand.Int());
	}
}

func(r * File) ConfusionImportTable()error{
	impt:=r.Base.ToIMAGE_IMPORT_DESCRIPTOR_Ptr(r.RVAToFVA(r.ImportTableOffset))
	var i uint32=0
	end:=IMAGE_IMPORT_DESCRIPTOR{0,0,0,0,0}
	var pName *byte
	
	var funcAddr uintptr=0
	var funcIndex uint32=0
	var flag uint64 =0
	
	for{

		imtTableEntry:=impt.Get(i);
		if *imtTableEntry==end {
			break
		}
		
		pName=r.Base.ToBytePtr(r.RVAToFVA(imtTableEntry.Name)).Get(0)
		
		name:=GetByteSlice(pName);
		ImportEncrypt(name)
		WriteByteSlice(name,pName)
		//加密
		//写回
		
		//log.Printf("%s-%p\r\n",name,pdllBase)
		pFuncName:=imtTableEntry.OriginalFirstThunk
		
		if imtTableEntry.OriginalFirstThunk==0{
			pFuncName=imtTableEntry.FirstThunk
		}
		pThnkData:=r.Base.ToIMAGE_THUNK_DATA_Ptr(r.RVAToFVA(pFuncName));
		
		if pThnkData.Get(0).AddressOfData==0{
			return errors.New("AddressOfData 为 0error")
		}
		funcAddr=0
		funcIndex=0
		
		for{
			data:=pThnkData.Get(funcIndex).AddressOfData
			if data==0{
				break
			}
			if unsafe.Sizeof(funcAddr)==4{
				flag=uint64(data& 0x80000000)
			}else{
				flag=uint64(data) & 0x8000000000000000
			}
			if flag==0{
				
				
				//log.Printf("%d-%p\r\n",data& 0xffff,funcAddr)
				start:=&r.Base.ToIMAGE_IMPORT_BY_NAME_Ptr(r.RVAToFVA(uint32(data))).Get(0).Name[0];
				pFuncName:=GetByteSlice(start)
				//加密
				ImportEncrypt(pFuncName)
				WriteByteSlice(pFuncName,start)
				//写回
				//log.Printf("%s-%p\r\n",pFuncName,funcAddr)
			}
			
			
			
			funcIndex=funcIndex+1
		}
		i=i+1
	}
	return nil

}