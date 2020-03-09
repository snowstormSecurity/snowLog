function write-snowLog { <#
    .EXTERNALHELP snowlog.psm1-Help.xml
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)][string]$logName,
        [parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)][Alias("step")][string]$action,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)][string]$status,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 4)][Alias("uOrigin")][string]$userOrigin=(whoami),
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 5)][Alias("uImpacted")][string]$userImpacted=$global:userImpacted,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 6)][Alias("ipOrigin","hOrigin")][string]$hostOrigin=$global:hostOrigin,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 7)][Alias("ipImpacted","hImpacted")][string]$hostImpacted=$global:hostImpacted,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 8)][string]$command=$global:command,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$Hash=$global:Hash,
		[Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 11)][String]$group=$global:group,
		[Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 12)][String]$domain=$global:domain,
		[Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 13)][String]$sender=$global:Sender,
        [Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 14)][Alias("process")][String]$processName=$global:processName,
		[Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 15)][String]$processID=$global:processID,
		[Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 16)][Alias("level","importance")][String]$severity=$global:severity,
        [Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 17)][String]$protocol=$global:protocol,
        [Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 18)][Alias("filetype")][String]$object=$global:object,
        [Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 19)][Alias("filename","file")][String]$objectName=$global:objectName,
        [Parameter(mandatory = $false, ValueFromPipeline = $false, Position = 20)][Alias("msg","content")][String]$message,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 99)][string]$extension=".log",
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 100)][string]$rootFolder=$global:snowLogRoot
    )

    # Test for access to rootFolder
    try {
        if($false -eq (Test-Path $rootFolder)){
            New-Item -path $rootFolder -ItemType Directory | out-null
        }
    }
    catch {
        Write-Error "Unable to create $rootDirectory"
        break
    }

    # Test for rootFolder + logName folder
    $logFolderName = Join-path -path $rootFolder -ChildPath $logName
    try {
        if($false -eq (Test-Path $logFolderName)){
            New-Item -path $logFolderName -ItemType Directory | out-null
        }
    }
    catch {
        Write-Verbose "Unable to create $logFolderName" -verbose
        break
    }

    # Define Activity Time
    $logDateTime = Get-Date -format "yyyy-MM-dd"

    # Set Output File Path
    $outputFile = Join-path -path $logFolderName -childPath ($logDateTime + $extension)

    # Test for rootFolder\LogName\YYYY-MM-DD.log
    try {
        if($false -eq (Test-Path $outputFile)){
            New-Item -path $outputFile -ItemType File | out-null
        }
    }
    catch {
        Write-Verbose "Unable to create $outputFile" -verbose
        break
    }        

    # Define Object
    $diagOutputProperties = [ordered]@{
        DateTime = Get-Date
        LogName = $logName
        Action = $action
        Status = $status
        ProcessName = $processName
        uOrigin = $userOrigin
        uImpacted = $userImpacted
        hOrigin = $hostOrigin
        hImpacted = $hostImpacted
        Command = $command
        Hash = $Hash
        Group = $group
        Domain = $domain
        Sender = $sender
        ProcessID = $processID
        Severity = $severity
        Protocol = $protocol
        Object = $object
        ObjectName = $objectName
        Message = $message
    }
    
    $diagOutput = New-Object psObject -Property $diagOutputProperties
    $diagOutput.psobject.TypeNames[0] = 'SnowLog.Log'
    
    # Output Object to File Path
    $diagOutput | export-csv -path $outputFile -Append

}
function show-snowLogVariables { <#
    .EXTERNALHELP snowlog.psm1-Help.xml
#>
    [CmdletBinding()]
    param(
    )
    Write-verbose "Log Root         = $global:snowLogRoot" -verbose
    Write-verbose "LogName          = $global:logName" -Verbose
    Write-verbose "Action           = $global:action" -Verbose
    Write-verbose "userOrigin       = $global:userOrigin" -Verbose
    Write-verbose "userImpacted     = $global:userImpacted" -Verbose
    Write-verbose "hostOrigin       = $global:hostOrigin" -Verbose
    Write-verbose "hostImpacted     = $global:hostImpacted" -Verbose
    Write-verbose "sourceHash       = $global:sourceHash" -Verbose
    Write-verbose "destinationHash  = $global:destinationHash" -Verbose
    Write-verbose "group            = $global:group" -Verbose
    Write-verbose "domain           = $global:domain" -Verbose
    Write-verbose "Sender           = $global:Sender" -Verbose
    Write-verbose "processName      = $global:processName" -Verbose
    Write-verbose "processID        = $global:processID" -Verbose
    Write-verbose "severity         = $global:severity" -Verbose
    Write-verbose "protocol         = $global:protocol" -Verbose
    Write-verbose "object           = $global:object" -Verbose
    Write-verbose "objectName       = $global:objectName" -Verbose



}
function clear-snowLogVariables { <#
    .EXTERNALHELP snowlog.psm1-Help.xml
#>
    [CmdletBinding()]
    param(

    )
    $global:logName = $null
    $global:action = $null
    $global:userOrigin = $null
    $global:userImpacted = $null
    $global:hostOrigin = $null
    $global:hostImpacted = $null
    $global:sourceHash = $null
    $global:destinationHash = $null
    $global:group = $null
    $global:domain = $null
    $global:Sender = $null
    $global:processName = $null
    $global:processID = $null
    $global:severity = $null
    $global:protocol = $null
    $global:object = $null
    $global:objectName = $null

    show-snowLogVariables
}

function set-snowLogRoot { <#
    .EXTERNALHELP snowlog.psm1-Help.xml
#>
    [CmdletBinding()]
    param(
    [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][Alias("path")][string]$logRoot

    )
    try {
        IF(Get-Item $logRoot){
            $fullPath = (Get-Item $logRoot).FullName
            Write-verbose ('Setting $snowLogRoot to: ' + $fullPath) -verbose
            $global:snowLogRoot = $fullPath
        }
    }
    catch {
        Write-Warning "Log Root Not Found: $logRoot"
        Write-Warning "Use of write-snowLog will attempt to create directory upon initial usage."
    }
}

function get-snowLog { <#
    .EXTERNALHELP snowlog.psm1-Help.xml
#>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)][string]$logName,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][string]$logdate,
        [Alias("mostRecent","newest")][switch] $current,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 99)][string]$extension=".log",
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 100)][string]$rootFolder=$global:snowLogRoot
    )
    # Test for $snowLogRoot
    if($false -eq (Test-path $rootFolder)){
        Write-Error "Unable to find: $rootFolder"
        break
    }

    # Test for rootFolder + logName folder
    $logFolderName = Join-path -path $rootFolder -ChildPath $logName
    if($false -eq (Test-Path $logFolderName)){
        Write-Error "Unable to find logName: $logName"
        break
    }

    # If Current
    if($current){
        $fileFullName = (Get-childitem -path $logFolderName -file | sort-object LastWriteTime)[-1].FullName
    }
    else{
        $logFileFullname = Join-path -path $logFolderName -ChildPath ($logdate + $extension)
        if($false -eq (Test-Path $logFileFullname)){
            Write-Error "Unable to find log: $logFileFullname"
            break
        }
        $fileFullName = (Get-childitem -path $logFileFullname -file | sort-object LastWriteTime)[-1].FullName
    }  # Find most recent
    Import-CSV -path $fileFullName
}

Export-ModuleMember -Function *

$global:snowLogRoot = join-path -path $env:temp -ChildPath 'Logs'
Write-verbose "Current root log folder set as: $global:snowLogRoot " -Verbose
Write-Verbose "To change root log folder, run: set-snowLogRoot -logRoot <newPath>" -verbose