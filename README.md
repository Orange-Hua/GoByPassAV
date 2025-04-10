GoByPass
  This tool is designed to assist security engineers in developing anti - detection tools to test system security.
  
  The usage method is as follows:
    
    1.Call the ReadPayloadAndWriteToLoader function in the main main.go file.
      The first parameter is the full path of the PE file,
      the second parameter is the CPU architecture (either 32 - bit or 64 - bit), 
      and the third parameter is related to the DLL.
      If you want to execute a certain exported function of the DLL, fill in the name of the exported function; 
      otherwise, leave it blank. After running, a loader.go file will be generated in the payload directory.
    
    2.Call the Gen1 function in loader.go from main.go. 
         After executing go build -ldflags " -H=windowsgui" main.go, you can generate an anti - detection program.

Statement:

This tool is only intended for technical research and authorized offensive and defensive projects. Users are required to comply with the Cybersecurity Law  and must not use it for any illegal activities. If the tool is used for other purposes, the user shall bear all legal responsibilities and joint liabilities. The author and the publisher shall not bear any legal responsibilities and joint liabilities!


!![Uploading main_shellcode扫描结果.png…]()

!![main_shellcode动态执行](https://github.com/user-attachments/assets/da487d70-65fb-4552-8681-95bd993a2c74)

!![vt](https://github.com/user-attachments/assets/b2ab5fe1-f72d-4430-b37d-6c6eb83145c5)

!![wb](https://github.com/user-attachments/assets/7a78c15d-df29-4cc4-aef7-45598354b008)





