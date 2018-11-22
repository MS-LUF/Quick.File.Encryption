# Quick.File.Encryption
a toolbox to encrypt automatically file in a folder (FileSystemWatcher) using Cryptographic Message Syntax format (CMS) and a public key (certificate)

(c) 2018 lucas-cueff.com Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).

## Description
This toolbox can be used to watch (FileSystemWatcher - inotify) a folder and encrypt automatically new file created using the CMS format https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax and a valid public key (OID and key usage speaking)

## Note
To use this module you need Powershell Core or PowerShell 5 for Windows.
You need also a valid certificate (OID 1.3.6.1.4.1.311.80.1 aka DOCUMENT_ENCRYPTION), see https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/protect-cmsmessage?view=powershell-6
- you can use my OpenSSL sample conf file to generate a DEV CA and generate valid user encryption certificate to test it :)

## Documentation
To do ;)

## Exported Functions and Alias
### Functions
- ConvertFrom-Base64ToBinaryFile
- ConvertFrom-BinaryFileToBase64
- Trace-FileSystemFolder                                                       

## Use the toolbox
### Encrypt all text file in your C:\temp folder using test.cer public key
Use Watch-And_Encrypt.ps1 with C:\temp as TargetFolder parameter, c:\temp2\test.cer as TargetCertificate parameter and "*.txt" as FileFilter parameter
```
	C:\PS> .\Watch-And-AutoEncrypt.ps1 -TargetFolder C:\temp -TargetCertificate c:\temp2\test.cer -FileFilter "*.txt"
```
### Encrypt all binaries file in your c:\temp folder using test.cer public key
Use Watch-And_Encrypt.ps1 with C:\temp as TargetFolder parameter, c:\temp2\test.cer as TargetCertificate parameter , "*.exe" as FileFilter parameter and IsBinaryFile switch
```
	C:\PS> .\Watch-And-AutoEncrypt.ps1 -TargetFolder C:\temp -TargetCertificate c:\temp2\test.cer -FileFilter "*.exe" -IsBinaryFile
```
### Result
the source file is copied and encrypted into *.enc file and source file is automatically removed after that.