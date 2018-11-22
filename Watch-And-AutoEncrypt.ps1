#
# Created by: lucas.cueff[at]lucas-cueff.com
# v0.1 : 
# - First Release
#
# Released on: 22/11/2018
#
#'(c) 2018 lucas-cueff.com - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'

<#
	.SYNOPSIS 
	a toolbox to encrypt automatically file in a folder (FileSystemWatcher) using Cryptographic Message Syntax format (CMS) and a public key (certificate)

	.DESCRIPTION
    This toolbox can be used to watch (FileSystemWatcher - inotify) a folder and encrypt automatically new file created using the CMS format https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax and a valid public key (OID and key usage speaking)
    
    .NOTES
    To use this module you need Powershell Core or PowerShell 5 for Windows.
    You need also a valid certificate (OID 1.3.6.1.4.1.311.80.1 aka DOCUMENT_ENCRYPTION), see https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/protect-cmsmessage?view=powershell-6
    - you can use my OpenSSL sample conf file to generate a DEV CA and generate valid user encryption certificate to test it :)
    
    .EXAMPLE
    Encrypt all text file in your C:\temp folder using test.cer public key
    Use Watch-And_Encrypt.ps1 with C:\temp as TargetFolder parameter, c:\temp2\test.cer as TargetCertificate parameter and "*.txt" as FileFilter parameter
	C:\PS> .\Watch-And-AutoEncrypt.ps1 -TargetFolder C:\temp -TargetCertificate c:\temp2\test.cer -FileFilter "*.txt"
#>
[cmdletbinding()]
Param (
    [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $False)]
    [ValidateScript({
        if( -not ($_ | Test-Path)){
            throw "Folder does not exist"
        }
        return $true
    })]
        [System.IO.FileInfo]$TargetFolder,
    [Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $False)]
    [ValidateScript({
        if( -not ($_ | Test-Path)){
            throw "Certificate does not exist"
        }
        return $true
    })]
        [string]$TargetCertificate,
    [Parameter(Mandatory = $True, Position = 2, ValueFromPipeline = $False)]
    [ValidateNotNullOrEmpty()]
        [string]$FileFilter,
    [Parameter(Mandatory = $False, Position = 3, ValueFromPipeline = $False)]
        [switch]$IsBinaryfile
)
Function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
If ($host.version.Major -lt 5) {
    throw "PowerShell version not up to date, please upgrade it before using this script"
}
$custommodule = Join-Path (Get-ScriptDirectory) "QuickFileEncryption.psm1"
if (-not (test-path $custommodule)) {
    throw "Missing encryption PowerShell module"
}
import-module $custommodule
If ($IsBinaryfile.IsPresent) {
    $script:action = {
        import-module $event.MessageData.module
        If ((-not (test-path "$($Event.SourceEventArgs.FullPath).enc")) -and (test-path $event.MessageData.certificate)) {
            ConvertFrom-BinaryFileToBase64 -path $Event.SourceEventArgs.FullPath |Protect-CmsMessage -To $event.MessageData.certificate -OutFile "$($Event.SourceEventArgs.FullPath).enc"
            Remove-Item -path $Event.SourceEventArgs.FullPath -Force
        }
    }
} Else {
    $script:action = {
        If ((-not (test-path "$($Event.SourceEventArgs.FullPath).enc")) -and (test-path $event.MessageData.certificate)) {
            Protect-CmsMessage -To $event.MessageData.certificate -Path $Event.SourceEventArgs.FullPath -OutFile "$($Event.SourceEventArgs.FullPath).enc"
            Remove-Item -path $Event.SourceEventArgs.FullPath -Force
        }
    }
}
$MessageData = New-Object -typename psobject -Property @{
    certificate = $TargetCertificate
    module = $custommodule
}
Trace-FileSystemFolder -path $TargetFolder -EventName @("Created") -Recurse -Action $Action -Filter $FileFilter -MessageData $MessageData