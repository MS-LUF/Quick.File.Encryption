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
Function Trace-FileSystemFolder {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]
        [ValidateScript({
            if( -Not ($_ | Test-Path) ){
                throw "Folder does not exist"
            }
            return $true
        })]
            [System.IO.FileInfo]$Path,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateSet('Changed','Created','Deleted','Renamed')]
            [string[]]$EventName,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
            [string]$Filter,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
            [System.IO.NotifyFilters]$NotifyFilter,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
            [switch]$Recurse,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
            [scriptblock]$Action,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
            [psobject]$MessageData
    )
    process {
        $FileSystemWatcher  = New-Object System.IO.FileSystemWatcher
        $FileSystemWatcher.Path = $Path
        If ($Filter) {
            $FileSystemWatcher.Filter = $Filter
        }
        If ($NotifyFilter) {
            $FileSystemWatcher.NotifyFilter =  $NotifyFilter
        }
        If ($Recurse) {
            $FileSystemWatcher.IncludeSubdirectories =  $True
        }
        If (-NOT $Action) {
            $Action  = {
                Switch  ($Event.SourceEventArgs.ChangeType) {
                    'Renamed'  {
                        $Object  = "{0} was  {1} to {2} at {3}" -f $Event.SourceArgs[-1].OldFullPath,
                        $Event.SourceEventArgs.ChangeType,
                        $Event.SourceArgs[-1].FullPath,
                        $Event.TimeGenerated
                    }
                    Default  {
                        $Object  = "{0} was  {1} at {2}" -f $Event.SourceEventArgs.FullPath,
                        $Event.SourceEventArgs.ChangeType,
                        $Event.TimeGenerated
                    }  
                }
                $WriteHostParams  = @{
                    ForegroundColor = 'Green'
                    BackgroundColor = 'Black'
                    Object =  $Object
                }
                Write-Host  @WriteHostParams
            }
        }
        $ObjectEventParams  = @{
            InputObject =  $FileSystemWatcher
            Action =  $Action
        }
        If ($MessageData) {
            $ObjectEventParams.Add('MessageData',$MessageData)
        }
        ForEach  ($Item in $EventName) {
            $ObjectEventParams.EventName = $Item
            $ObjectEventParams.SourceIdentifier =  "File.$($Item)"
            Write-Verbose  "Starting watcher for Event: $($Item)"
            $Null  = Register-ObjectEvent  @ObjectEventParams
        }
    }
} 
Function ConvertFrom-BinaryFileToBase64 {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] 
        [ValidateScript({
            if( -Not ($_ | Test-Path) ){
                throw "File does not exist"
            }
            return $true
        })]
            [System.IO.FileInfo]$Path
    )
    process {
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
    }
}
Function ConvertFrom-Base64ToBinaryFile {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] 
            [string]$String,
        [Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $False)]
        [ValidateScript({
            If (($_ | Test-Path)) {
                throw "File already exists"
            }
            return $true
        })]
            [System.IO.FileInfo]$OutputFilePath
    )
    process {
        [IO.File]::WriteAllBytes($OutputFilePath, [Convert]::FromBase64String($String))
    }
}

Export-ModuleMember -Function Trace-FileSystemFolder, ConvertFrom-Base64ToBinaryFile, ConvertFrom-BinaryFileToBase64