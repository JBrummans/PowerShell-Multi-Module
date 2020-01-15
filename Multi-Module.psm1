#Requires -Version 5.0

<#=========Multi-Module.psm1===========
    Original Creator:
        JBrummans
    Description:
        Collection of functions for use within a Windows Enviroment. Module contains custom and sourced code.

    See README for details
#>

Function Get-MMInfo {

    <#
    .SYNOPSIS
    Searches Multi-Module for functions and displays the name and synopsis of each.
    #>

    Process{
        $Name = (get-command -Module Multi-Module).name
        $Array = @()
        Foreach($n in $Name){
            $Synopsis = (get-help $n | Select-object synopsis).synopsis
            $Array += [PSCustomObject]@{
                Name = $n
                Synopsis = $Synopsis
            }
        }
        Return $Array
    }
}

Function Show-MMPercentage {

    <#
    .SYNOPSIS
    Function that accepts a value between 0-100 and displays as a simple bar chart.

    .EXAMPLE
    Show-Percentage 40 200
    Passes two parameters to the function. The first is the smaller value. The second is the total/max value. The function will calculate the percentage of 40 out of 200 and graph the result.

    .EXAMPLE
    Show-Percentage 50
    Passes a single parameter. The function assumes this value is between 1-100 and will graph it out of 100.
    #>

    [cmdletbinding()]
    param([long]$a, [long]$b=100)
    Process{
        If($b -ge $a){
            $amount = $a/$b*100/5
            $Used = "#"*($Amount)
            $Unused = " "*(20-$Amount)
            $graph = '['+$Used+$Unused+']'
        }Else{
            $graph = '[   GRAPHING ERROR   ]'
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Invalid paramaters. Total value is less then provided." -Severity "Error"

        }
        Return $graph
    }
}

Function Get-MMStats {

    <#
    .SYNOPSIS
    Displays computer resource stats.

    .DESCRIPTION
    Displays computer resource stats. Refreshes every few seconds. Loops until user terminates function manually.
    #>

    #Get total ram in system
    $TotalRam = (Get-Ciminstance Win32_OperatingSystem).TotalVisibleMemorySize
    $a = 0

    #Set arrays
    $CPUarr = @()
    $RAMarr = @()
    $HDDarr = @()

    While($a -eq 0) {
        #Get CPU usage
        $CPUCurrent = (Get-WmiObject win32_processor).LoadPercentage
        $CPUarr += $CPUCurrent
        $CPUavg = [math]::round((($CPUarr | Measure-Object -Average).average),2)

        #Get Ram usage
        $FreeRam = (Get-Ciminstance Win32_OperatingSystem).FreePhysicalMemory
        $RamPercFree = [math]::Round(($FreeRam/$totalRam)*100,0)
        $RamPercUsed = 100-$RamPercFree
        $RAMArr += $RamPercUsed
        $RAMAvg = [math]::round((($RAMArr | Measure-Object -Average).average),2)

        #Get hdd utilisation
        $HddPerc = (Get-WMIObject -Class "Win32_PerfFormattedData_PerfDisk_PhysicalDisk" -Filter 'Name = "_Total"').PercentDiskTime
        $HDDarr += $HddPerc
        $HDDAvg = [math]::round((($HDDarr | Measure-Object -Average).average),2)

        #Get list of top 10 processes
        $TopProcess = Get-MMTopProcess 10

        $CPUgraph = Show-MMPercentage $CPUCurrent
        $RAMgraph = Show-MMPercentage $RamPercUsed
        $HDDgraph = Show-MMPercentage $HddPerc

        Clear-Host
        Write-host CPU Util: $CPUCurrent '%'
        $CPUgraph
        Write-Host CPU Avg: $CPUAvg

        Write-Host ""

        Write-host RAM Util: $RamPercUsed '%'
        $RAMgraph
        Write-host RAM Avg: $RAMAvg

        Write-Host ""
        Write-Host HDD Util: $HddPerc '%'
        $HDDgraph
        Write-host HDD Avg: $HDDAvg

        $TopProcess
    }
}

Function Get-MMTopProcess {

    <#
    .SYNOPSIS
    Lists the top processes ordered by CPU utilisation. Limits to paramater passed.
    #>

    [cmdletbinding()]
    param([int]$Top=10)

    $TopProcess = (Get-Process | Sort-Object CPU -desc | Select-Object -first $top | Format-Table  ProcessName, ID, CPU)
    Return $TopProcess
}

Function Get-MMTVID {

    <#
    .SYNOPSIS
    Checks registry of remote computer and returns the TeamViewer ID number.

    .LINK
    https://community.spiceworks.com/scripts/show/3990-retrieve-teamviewer-client-id-via-powershell

    .EXAMPLE
    Get-MMTVID -Hostname COMPUTERNAME
    Finds the TV ID of a remote computer by its name and displays it.

    .EXAMPLE
    Get-MMTVID -Hostname 192.168.0.1 -Copy
    Finds the TV ID of a remote computer by its IP, displays it and copies it to clipboard.

    .EXAMPLE
    Get-MMTVID -Hostname COMPUTERNAME -AutoConnect
    Finds the TV ID of a remote computer by its name, displays it and attempts to open Teamviewer and connect to said ID.
    #>

    param(
        [string] $Hostname,
        [switch] $Copy,
        [switch] $AutoConnect
        )

    #If no hostname provided, assume local computer
    If (!$Hostname){
        $Hostname = $env:COMPUTERNAME
    }

    #Start Remote Registry Service
    If ($Hostname -ne $env:COMPUTERNAME){
        $Service = Get-Service -Name "Remote Registry" -ComputerName $Hostname
        $Service.Start()
    }

    #Suppresses errors (comment to disable error suppression)
    $ErrorActionPreference = "SilentlyContinue"

    #Attempts to pull clientID value from remote registry and display it if successful
    $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Hostname)
    $RegKey= $RegCon.OpenSubKey("SOFTWARE\\WOW6432Node\\TeamViewer")
    $ClientID = $RegKey.GetValue("clientID")

    #Stop Remote Registry service
    If ($Hostname -ne $env:COMPUTERNAME) {
        $Service.Stop()
    }

    #Display results
    Write-Host
    If (!$clientid) {
        Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Unable to retrieve clientID value via remote registry" -Severity "Error" -Display
    }Else{
        Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "TeamViewer client ID for $Hostname is $Clientid" -Severity "Information" -Display
        
        #Copy to clipboard
        If ($copy){
            $ClientID | clip
        }

        If($AutoConnect){
            $TV86 = Test-Path "C:\Program Files (x86)\TeamViewer\TeamViewer.exe"
            $TV64 = Test-Path "C:\Program Files\TeamViewer\TeamViewer.exe"
            If($TV86){
                $TVLocation = "C:\Program Files (x86)\TeamViewer\TeamViewer.exe"
                & $TVLocation -i $ClientID
            } Elseif($TV64){
                $TVLocation = "C:\Program Files\TeamViewer\TeamViewer.exe"
                & $TVLocation -i $ClientID
            } Else {
                #Write-Host "Error: Teamviewer was not located on this computer" -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Teamviewer was not located on this computer" -Severity "Error" -Display
            }
        }
    }
    Write-Host
}

Function Unlock-MMUser {

    <#
    .SYNOPSIS 
    Checks if the user is locked in AD. If yes, unlock.

    .DESCRIPTION
    Checks if the user is locked in AD. If yes, unlock. Accepts "-r" as a switch to loop until manually closed.

    .NOTES
    Requires AD Module

    .EXAMPLE
    Unlock-MMUser jsmith
    Checks jsmith for lockouts and unlocks if locked.

    .EXAMPLE
    Unlock-MMUser jsmith -r
    Checks jsmith for lockouts and unlocks if locked. Checks every 15 seconds until closed.
    #>

    [cmdletbinding()]
    param ([String]$user,[switch]$repeat)

    process {
        $a = 0
        do {
            Write-Host "Checking..." -ForegroundColor Yellow
            $Userinfo = Get-ADUser -Filter * -Properties LockedOut |
            Where-Object { $_.SAMAccountName -like "*$user*" } |
            Select-Object -Property SamAccountName, DistinguishedName, LockedOut #| Out-GridView -PassThru
            $lockstatus = $Userinfo.lockedout

            if ($lockstatus -eq "True") {
                $date = Get-MMTimeStamp
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Account locked (Date:" $Date")" -Severity "Information" -Display
                Write-Host "Unlocking Account"
                Try{
                    Unlock-ADAccount $Userinfo.SamAccountName
                }Catch{
                    Write-Host "An Error has occured. What a bummer... Is AD module installed and do you have access to AD?" -ForegroundColor red
                    Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error" -Display
                }
            } Else {
                Write-Host -f Green "Account is Not Locked out"
            }
            If($repeat -eq $true){
                Write-Host "Waiting..." -ForegroundColor Yellow
                start-sleep 15
            }Else{
                $a = 1
            }
        } until ($a -eq 1)
    }
}

Function Get-MMHostList {

    <#
    .SYNOPSIS
    Searches the domain for Hyper V hosts and returns a list.

    .NOTES
    Requires AD module.

    .LINK
    https://techibee.com/powershell/find-list-of-hyper-v-servers-in-domain-using-powershell/2100
    #>

    [cmdletbinding()]
    param()
    Try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } Catch {
        Write-Warning "Failed to import Active Directory module. Exiting"
        Return
    }

    Try {
        $Hypervs = Get-ADObject -Filter 'ObjectClass -eq "serviceConnectionPoint" -and Name -eq "Microsoft Hyper-V"' -ErrorAction Stop
    } Catch {
        Write-Error "Failed to query active directory. More details : $_"
        Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
    }
    Return $Hypervs
}

Function Get-MMHOSTS {

    <#
    .SYNOPSIS
    Searches the domain for Hyper V hosts and displays a list.

    .NOTES
    Requires AD module.

    .LINK
    https://techibee.com/powershell/find-list-of-hyper-v-servers-in-domain-using-powershell/2100
    #>

    [cmdletbinding()]
    param()

    $Hypervs = Get-MMHostList

    foreach($Hyperv in $Hypervs) {
        $temp = $Hyperv.DistinguishedName.split(",")
        $HypervDN = $temp[1..$temp.Count] -join ","
        $Comp = Get-ADComputer -Id $HypervDN -Prop *
        $OutputObj = New-Object PSObject -Prop (
        @{
        HyperVName = $Comp.Name
        OSVersion = $($comp.operatingSystem)
        })
        $OutputObj
    }
}

Function Get-MMVMS {

    <#
    .SYNOPSIS
    Searches AD for hosts and their VMs. Displays list of VMs grouped by host.

    .LINK
    https://techibee.com/powershell/find-list-of-hyper-v-servers-in-domain-using-powershell/2100

    .EXAMPLE
    Get-MMVMS
    Lists all hosts and their VM's.
    #>

[cmdletbinding()]
param()

    $Credential = Get-Credential

    $Hypervs = Get-MMHostList

    foreach($Hyperv in $Hypervs) {
        $temp = $Hyperv.DistinguishedName.split(",")
        $HypervDN = $temp[1..$temp.Count] -join ","
        $Comp = Get-ADComputer -Id $HypervDN -Prop *
        $OutputObj = New-Object PSObject -Prop (
            @{
                HyperVName = $Comp.Name
                OSVersion = $($comp.operatingSystem)
            }
            )
            foreach($hyperVName in $OutputObj){
                Write-Host  "HostName:" $OutputObj.HyperVName -ForegroundColor Yellow
                Invoke-Command -ComputerName $OutputObj.HyperVName -ScriptBlock {Get-VM | Select-Object VMName, Uptime} -Credential $Credential
            }
        }
}

Function Export-MMSineList {

    <#
    .SYNOPSIS
    Exports a csv file with a list of users, names, numbers etc required for updating sine. Some modification is still required.

    .NOTES
    Requires AD module.

    .EXAMPLE
    Export-MMSineList
    Exports a CSV file to C:\Temp.
    #>

    Write-Host "Exporting list to C:\temp\ADExport.csv"
    Get-ADUser -Filter * -Properties EmailAddress, givenName, sn, Mobile | Select-Object EmailAddress, givenName, sn, Mobile | Export-CSV "C:\temp\ADExport.csv"
}

Function Get-MMMulti-Info {

    <#
    .SYNOPSIS
    DEPRECATED. Replacement Get-MMSystemInfo. Searches computer for mulitple peices of infomation which may be helpful when diag issues. Displays info as a list.

    .NOTES
    Created by Jbrummans
    This Function was initially created when I first started learning powershell. It has been replaced by Get-MMSystemInfo. Keeping it here for nostalgia reasons only.
    Several sources are referenced thoughout the script.

    Old Notes Below:
    To do: display last boot. Format and clean code.
    Date Modified: 26/06/2018 Replaced percentage with Show-MMPercentage function. Added Logon Server and OU
    Date Modified: 31/12/2016 Added Domain/workgroup
    Date Modified: 29/12/2016 Added DNS, GPU and Resolution, some formatting, fixed gatewayIP, Commented out Public IP for now.
    Date modified: 15/02/2016 Initial creation
    #>

    write-host =============================================
    write-host =+=+=+=+=+=+=+= -NoNewLine
    Write-Host "Multi-Info Tool DEPRECATED. Use Get-MMSystemInfo instead." -ForegroundColor Red -NoNewLine
    Write-Host =+=+=+=+=+=+=+=
    write-host =================== -NoNewLine
    Write-Host "V0.6" -NoNewLine -ForegroundColor Yellow
    Write-Host ======================

    Write-Host
    #Write-Host -NoNewLine "`r0% complete" #Progress meter
    Show-MMPercentage 0

    #==============General Computer details=================
    $PcManu = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    $Model = (Get-WmiObject -Class Win32_ComputerSystem).Model
    $PcName = (Get-WmiObject -Class Win32_ComputerSystem).Name #alternative $env:COMPUTERNAME
    $Primary = (Get-WmiObject -Class Win32_ComputerSystem).PrimaryOwnerName
    $Memory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1000/1000
    $Memory = [System.Math]::Round($Memory)

    Show-MMPercentage 10

    #=============HDD space/capacity=====================
    #http://stackoverflow.com/questions/12159341/how-to-get-disk-capacity-and-free-space-of-remote-computer
    $disk = Get-WmiObject Win32_LogicalDisk -ComputerName localhost -Filter "DeviceID='C:'" |
    Select-Object Size,FreeSpace
    $ds = [math]::round($disk.Size/1000/1000/1000, 2)
    $fs = [math]::round($disk.FreeSpace/1000/1000/1000, 2)

    Show-MMPercentage 20

    #=============CPU details=====================

    $CpuManu = Get-WmiObject -Class Win32_Processor | Select-Object -Property [a-z]* -expand Manufacturer
    $CpuName = Get-WmiObject -Class Win32_Processor | Select-Object -Property [a-z]* -expand Name
    $CpuCore = Get-WmiObject -Class Win32_Processor | Select-Object -Property [a-z]* -expand NumberOfCores
    $CpuThread = Get-WmiObject -Class Win32_Processor | Select-Object -Property [a-z]* -expand NumberOflogicalProcessors

    Show-MMPercentage 30

    #==============OS Version==================
    #http://stackoverflow.com/questions/27316104/how-to-get-os-name-in-windows-powershell-using-functions
    $OS = (Get-WmiObject Win32_OperatingSystem).Name

    Show-MMPercentage 40

    #==============local IP address================
    #http://powershell.com/cs/blogs/tips/archive/2015/04/22/get-current-ip-address.aspx
    $ipaddress = [System.Net.DNS]::GetHostByName($null)
    foreach($ip in $ipaddress.AddressList){
      if ($ip.AddressFamily -eq 'InterNetwork'){
        $lip = $ip.IPAddressToString
      }
    }
    #=============DNS=================
    $DNS1,$DNS2 = (Get-WMIObject -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled=TRUE").DNSServerSearchOrder #Get DNS Servers

    #=============Default Gateway and DHCP===============
    $Gate = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | select-object DefaultIPGateway -expand DefaultIPGateway
    $IPstat = Get-NetIPAddress -AddressFamily IPv4 -PrefixLength 24 | Select-Object -expand PrefixOrigin #DHCP or STATIC

    Show-MMPercentage 70

    #==============Public IP address================
    #http://tfl09.blogspot.com.au/2008/07/finding-your-external-ip-address-with.html
    $wc=New-Object net.webclient
    $pip = $wc.downloadstring("http://checkip.dyndns.com") -replace "[^\d\.]"

    Show-MMPercentage 80

    #=============TimeZone/Date/Time===================
    $timezone =(Get-TimeZone).displayname # Get Timezone
    $date = Get-MMTimeStamp
    $ntp = w32tm /query /source #Get Time Server

    $CheckDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain #Checks if computer is a member of a domain
    If($CheckDomain -eq 'True'){
      $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
      $logonserver = $Env:LOGONSERVER
      $filter = "(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))" #https://stackoverflow.com/questions/11146264/get-current-computers-distinguished-name-in-powershell-without-using-the-active
      $OU = ([adsisearcher]$filter).FindOne().Properties.distinguishedname
    } Else {
        $workgroup = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    }

    #==================GPU====================
    #This will not work well with multiple cards as it will overwrite the variable.
    #https://community.spiceworks.com/topic/1543645-powershell-get-wmiobject-win32_videocontroller-multiple-graphics-cards
    foreach($gpu in Get-WmiObject Win32_VideoController){
      $graphics = $gpu.SYNOPSIS
    }
    $ResH = (Get-WmiObject win32_videocontroller).CurrentHorizontalResolution
    $ResV = (Get-WmiObject win32_videocontroller).CurrentVerticalResolution

    <#Requires elevation. Commenting out for now
    #Driver Checks for AMD and Nvidia
    #AMD
    $ati = Get-WindowsDriver -online | Where Providername -like *ati*
    $amd = Get-WindowsDriver -online | Where Providername -like *amd*

    #Nvidia
    $nvidia = Get-WindowsDriver -online | Where Providername -like *intel*
    #>

    #Write-Host -NoNewLine "`r60% complete"

    Show-MMPercentage 100

    Start-Sleep -s 1
    write-host "`r==============================================="
    write-host "SCAN COMPLETE" -ForegroundColor Yellow
    write-host "==============================================="
    write-host

    Write-Host ""
    Write-Host "============"
    Write-Host "System Info" -ForegroundColor Yellow
    Write-Host "============"

    Write-Host "Computer name:" $PcName
    Write-Host "OS Version:" $OS

    If($CheckDomain -eq 'True'){
        Write-host "Domain Name:" $domain
        Write-host "Logon Server:" $logonserver
        Write-host "Current Computer OU:" $OU
    } Else {
        Write-Host "WorkGroup Name:" $workgroup
    }

    #Write-Host "Domain or Workgroup:" $Domain
    Write-Host "Computer Manufacturer:" $PcManu
    Write-Host "Computer Model:" $Model
    Write-Host "Primary User of Machine:" $Primary
    write-host "Hard disk:" $fs "GB Free of "$ds "GB"
    Write-Host "Total Memory:" $Memory " MB"
    Write-Host "TimeZone:" $timezone
    Write-Host "System Time/Date:" $Date
    Write-Host "NTP Time Server: " $ntp

    Write-Host ""
    Write-Host "============"
    Write-Host "Graphics Info" -ForegroundColor Yellow
    Write-Host "============"

    Write-Host "Graphics Processor: " -Nonewline
    Write-Host $graphics -ForegroundColor Yellow
    Write-Host "Resolution (HxV):" -Nonewline
    Write-Host $ResH -NoNewLine -ForegroundColor Yellow
    Write-Host " X" -Nonewline -ForegroundColor Yellow
    Write-Host $ResV -ForegroundColor Yellow

    <#
    Write-Host "Software/Driver Checks:"
    If($ati -eq $null){
    Write-Host "No ATI Drivers found"
    }Else{
    Write-Host "ATI drivers Found"
    }
    If($amd -eq $null){
    Write-Host "No AMD Drivers found"
    }Else{
    Write-Host "AMD drivers Found"
    }
    If($nvidia -eq $null){
    Write-Host "No Nvidia Drivers found"
    }Else{
    Write-Host "Nvidia drivers Found"
    }
    #>

    Write-Host ""
    Write-Host "============"
    Write-Host "Network Info" -ForegroundColor Yellow
    Write-Host "============"
    Write-Host "Local IP Address:" $lip " (" $IPstat ")"
    #Write-Host "Static or Dynamic IP:" $IPstat
    write-host "Gateway Server:" $Gate
    Write-Host "DNS Servers:" $DNS1"," $DNS2
    write-host "Public IP address:" $pip

    Write-Host ""
    Write-Host "============"
    Write-Host "Processor Info" -ForegroundColor Yellow
    Write-Host "============"
    Write-Host "Processor Brand:" $CpuManu
    Write-Host "Processor Model:" $CpuName
    Write-host "Processor Cores:" $CpuCore
    Write-host "Processor Threads:" $CpuThread

    #Pause script and wait for response
    Write-Host
    Write-Host "END OF PROGRAM"
    Pause
}

Function Get-MMSystemInfo{
    
    <#
    .SYNOPSIS
    Gether system inforamtion for local or remote computer.

    .DESCRIPTION
    Gather information such as the Computer Name, OS, Memory, Disk, CPU, and Network Info.

    .NOTES
    Modified version of the below link. Added more points of Info and reduced the number of queries. Should speed up remote computer queries.
    Original Author: MosaicMK Software LLC
    Email: contact@mosaicMK.com
    Original Version: 2.0.2

    .LINK
    https://www.powershellgallery.com/packages/GetSystemInfo/2.0.2

    .EXAMPLE
    Get-MMSystemInfo
    Returns info of local machine

    .EXAMPLE
    Get-MMSystemInfo -ComputerName COMPUTERNAME
    Returns info of the remote machine
    #>
    
    param([string]$ComputerName = $env:computername)
    $Computer = $ComputerName

    #Gets computer info.
    $ComputerInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer
    $Domain = $ComputerInfo.Domain
    $ComputerModel = $ComputerInfo.Model
    $LoggedOnUser = $ComputerInfo.Username

    #Get list of users who have logged in before.
    $UserProfile = (Get-ChildItem \\$ComputerName\C$\users\).Name

    #Gets the OS info.
    $GetOS = Get-WmiObject -class Win32_OperatingSystem -computername $Computer
    $OS = $GetOS.Caption
    $OSArchitecture = $GetOS.OSArchitecture
    $OSBuildNumber = $GetOS.BuildNumber

    #Gets memory information.
    $Getmemoryslot = Get-WmiObject Win32_PhysicalMemoryArray -ComputerName $computer
    $Getmemorymeasure = Get-WMIObject Win32_PhysicalMemory -ComputerName $computer | Measure-Object -Property Capacity -Sum
    $MemorySlot = $Getmemoryslot.MemoryDevices
    $MaxMemory = $($Getmemoryslot.MaxCapacity/1024/1024)
    $TotalMemSticks = $Getmemorymeasure.count
    $TotalMemSize = $($Getmemorymeasure.sum/1024/1024/1024)

    #Get the disk info.
    $GetDiskInfo = Get-WmiObject Win32_logicaldisk -ComputerName $computer -Filter "DeviceID='C:'"
    $DiskSize = $([math]::Round($GetDiskInfo.Size/1GB))
    $FreeSpace = $([math]::Round($GetDiskInfo.FreeSpace/1GB))
    $UsedSapce =$([math]::Round($DiskSize-$FreeSpace))

    #Gets CPU info.
    $GetCPU = Get-wmiobject win32_processor -ComputerName $Computer
    $CPUName = $GetCPU.Name
    $CPUManufacturer = $GetCPU.Manufacturer
    $CPUMaxClockSpeed = $GetCPU.MaxClockSpeed
    $CPUCores = $GetCPU.NumberOfCores
    $CPULogical = $GetCPU.NumberOflogicalProcessors
    
    #Get IP address.
    $NetworkInfo = (Get-WmiObject win32_NetworkadapterConfiguration -ComputerName $Computer | Where-Object IPAddress -ne $null)
    $IPAddress = $NetworkInfo.ipaddress
    $DNS = $NetworkInfo.DNSServerSearchOrder
    $Gateway = $NetworkInfo.DefaultIPGateway
    
    #Determine DHCP enabled.
    If($networks.DHCPEnabled) {
        $IsDHCPEnabled = $true
    } Else {
        $IsDHCPEnabled = $false
    }

    #Resolve DNS server names.
    $DNSServerNames = @()
    ForEach($D in $DNS){
        Try{
            $DNSServerNames += [System.Net.Dns]::GetHostByAddress($D).Hostname
        }Catch{
            $DNSServerNames += "NA"
        }
    }

    #Gets BIOS info.
    $GetBios = Get-WmiObject win32_bios -ComputerName $Computer
    $BIOSName = $GetBios.Name
    $BIOSManufacturer = $GetBios.Manufacturer
    $BIOSVersion = $GetBios.Version
    $SerialNumber = $GetBios.SerialNumber

    #Gets Motherboard info.
    $GetMotherboard = Get-WmiObject Win32_BaseBoard -ComputerName $Computer
    $MotherBoardName = $GetMotherboard.Name
    $MotherBoardManufacturet = $GetMotherboard.Manufacturer
    $MotherBoardModel = $GetMotherboard.Model
    $MotherBoardProduct = $GetMotherboard.Product
    $MotherBoardSerial = $GetMotherboard.SerialNumber

    #Gets GPU info.
    $GetGPU = Get-WmiObject Win32_VideoController
    $GPUDevice = $GetGPU.name
    $ResH = $GetGPU.CurrentHorizontalResolution
    $ResV = $GetGPU.CurrentVerticalResolution

    #Gets system last boot and uptime.
    $Uptime, $LastBoot = Get-MMUptime -ComputerName $ComputerName
    
    #Define the object to hold the info.
    $ComputerInfo = New-Object -TypeName psobject
   
    #Add the items to the object.
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name ComputerModel -Value $ComputerModel
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name DomainName -Value $Domain

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $os
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name OSArchitecture -Value $OSArchitecture
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name OSBuild -Value $OSBuildNumber

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNS
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name Gateway -Value $Gateway
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name DNSServerNames -Value $DNSServerNames

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name LoggedInUsers -Value $LoggedOnUser
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name UserProfile -Value $UserProfile

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MemorySlots -Value $MemorySlot
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MaxMemory -Value "$MaxMemory GB"
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MemorySlotsUsed -Value $TotalMemSticks
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MemoryInstalled -Value "$TotalMemSize GB"

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name SystemDrive -Value $ENV:SystemDrive
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name DiskSize -Value "$DiskSize GB"
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name FreeSpace -Value "$FreeSpace GB"
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name UsedSpace -Value "$UsedSapce GB"

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name CPU -Value $CPUName
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name CPUManufacturer -Value $CPUManufacturer
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name CPUMaxClockSpeed -Value $CPUMaxClockSpeed
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name CPUCores -Value $CPUCores
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name CPULogical -Value $CPULogical

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MotherBoard -Value $MotherBoardName
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MotherBoardManufacturer -Value $MotherBoardManufacturet
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MotherBoardModel -Value $MotherBoardModel
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MotherBoardSerialNumber -Value $MotherBoardSerial
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name MotherBoardProduct -Value $MotherBoardProduct

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name BIOSName -Value $BIOSName
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name BIOSManufacturer -Value $BIOSManufacturer
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name BIOSVersion -Value $BIOSVersion
   
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name GPUDevice -Value $GPUDevice
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name HorizontalResolution -Value $ResH
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name VerticalResolution -Value $ResV

    $ComputerInfo | Add-Member -MemberType NoteProperty -Name Uptime -Value $Uptime 
    $ComputerInfo | Add-Member -MemberType NoteProperty -Name LastBootTime -Value $LastBoot

    Return $ComputerInfo
}

Function Get-MMExcuse {

    <#
    .SYNOPSIS
    Are you out of excuses? Let powershell help you.

    .LINK
    https://github.com/SpacezCowboy/Scripts/blob/master/PowerShell/Profiles-Modules/Profiles/Microsoft.PowerShell_profile.ps1
    #>

    $ex = (Invoke-WebRequest http://pages.cs.wisc.edu/~ballard/bofh/excuses -OutVariable excuses).content.split([Environment]::NewLine)[(get-random $excuses.content.split([Environment]::NewLine).count)]
    write-host "$ex" -Foregroundcolor Green
}

Function Set-MMCalanderPermission {

    <#
    .SYNOPSIS
    Sets the calendar permission for a delegates access.

    .DESCRIPTION
    Sets the calendar permission for a delegates access. Accepts a Owner, Delegate and Access Level paramater. Creates a session with the local exchange to apply the setting.

    .EXAMPLE
    Set-MMCalanderPermission -o jbrummans -d jsmith -a reviewer
    Sets jsmith to have access to JBrummans calendar as a reviewer

    .EXAMPLE
    Set-MMCalanderPermission
    Calling the function without paramaters (or incomplete paramaters) will cause it to prompt for input.
    #>

    [cmdletbinding()]
    param ([String]$Owner, [String]$Delegate, [String]$AccessLevel)

    process {
        Write-Host "Credentials are required to connect with Exchange:"
        $Credential = Get-Credential #Store credentials to connect to exchange server with.
        $Session = New-PSSession -ConfigurationName microsoft.exchange -ConnectionUri http://EXCHANGESERVERNAME/powershell/ -Authentication Kerberos -Credential $Credential
        Import-PSSession -Session $Session -CommandName Get-MailboxFolderPermission, Add-MailboxFolderPermission, Set-MailboxFolderPermission #Start the session.

        If ((-Not$Owner) -or (-Not$Delegate) -or (-not$AccessLevel)){
            Write-host "Required information missing! Please enter Owner, Delegate and Access Level" -ForegroundColor Red
            Write-host "(This can be skiped by passing Owner and Delegate usernames using -o, -d and -a paramaters respectively)" -ForegroundColor Yellow
            $Owner = Read-Host "Owner Username"
            $Delegate = Read-Host "Delegate Username"
            Write-Host "Access Level must be typed correctly in full."
            Write-Host "Examples: Editor (View, Create, Edit, Delete), Author (View, Create), Reviewer (View), AvailabilityOnly (Free/Busy Time)."
            $AccessLevel = Read-Host "Access Level"
        } Else {
            #Nothing for now I guess
        }

        do {

            Clear-Host
            $CurrentLevel = (Get-MailboxFolderPermission -Identity ${Owner}:\Calendar -User $Delegate).Accessrights
            Clear-Host

            If(!$CurrentLevel){
                Write-host "No Access Level currently set. Adding now" -ForegroundColor Green
                Add-MailboxFolderPermission -Identity ${Owner}:\calendar -user $Delegate -AccessRights $AccessLevel
            }Elseif($CurrentLevel){
                Write-host "Access Level is currently" $CurrentLevel". Modifying now" -ForegroundColor Green
                Set-MailboxFolderPermission -Identity ${Owner}:\calendar -user $Delegate -AccessRights $AccessLevel
            }Else{
                Write-Host "Woops... Something went wrong" -ForegroundColor Red
            }

            $NewLevel = (Get-MailboxFolderPermission -Identity ${Owner}:\Calendar -User $Delegate).Accessrights
            Write-host $Delegate "is now a(n)" $NewLevel "of" $Owner -ForegroundColor Green

            $loop = Read-Host "Another user delegation?: Y or N"
            If($loop -eq "Y"){
                Write-Host ""
                $Owner = Read-Host "Owner Username:"
                $Delegate = Read-Host "Delegate Username:"
                Write-Host "Access Level must be typed correctly. Examples Editor (View, Create, Edit, Delete), Author (View, Create), Reviewer (View)."
                $AccessLevel = Read-Host "Access Level:"
            }
        } until ($loop -eq "N")
        Remove-PSSession $Session #Close the session.
    }
}

Function Set-MMMailbox {

    <#
    .SYNOPSIS
    Get mailbox size of user and prompt to change.
    #>

    [cmdletbinding()]
    param ([String]$Username)

    process {

        $Session = Connect-MMExchange
        Import-PSSession -Session $Session -AllowClobber -CommandName Get-MailboxFolderPermission, Add-MailboxFolderPermission, Set-MailboxFolderPermission, Get-Mailbox, Set-Mailbox #Start the session.

        $CurrentSize = Get-Mailbox $Username | Format-List *Quota
        Write-Host "Current Mailbox Size:"
        Write-Host $CurrentSize

        $Choice = Read-Host "Change Mailbox Quota? (Y or N)"
        If($Choice -eq "Y" -or "y"){
            $IssueWarning = Read-Host "Issue warning at what size (in GB. EG 19)"
            $ProhibitSend = Read-Host "Prohibit Send/Rec at what size (in GB. EG 20)"
            $IssueWarning = $IssueWarning+"GB"
            $ProhibitSend = $ProhibitSend+"GB"
        }Else{
            Exit-MMFunction -Message1 "Exiting" -Colour1 "Red"
        }

        Set-Mailbox $USername -IssueWarningQuota $IssueWarning -ProhibitSendQuota $ProhibitSend `
        -ProhibitSendReceiveQuota $ProhibitSend -UseDatabaseQuotaDefaults $false
        $NewSize = Get-Mailbox $Username | Select-Object IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota | Format-List *Quota

        Clear-Host
        Write-Host "Previous Mailbox Size was:" -ForegroundColor Yellow
        Write-Host $CurrentSize -ForegroundColor yellow
        Write-Host "New Mailbox Size was:" -ForegroundColor Green
        Write-Host $NewSize -ForegroundColor green
    }
}

Function Connect-MMExchange{

    <#
    .SYNOPSIS
    Establishes session to the exchange server.
    #>

    [CmdletBinding()]
    Param ()

    process {

    Write-Host "Credentials are required to connect with Exchange:"
    $Credential = Get-Credential #Store credentials to connect to exchange server with.
    $Session = New-PSSession -ConfigurationName microsoft.exchange -ConnectionUri http://EXCHANGESERVERNAME/powershell/ -Authentication Kerberos -Credential $Credential
    Return $Session
    }
}

Function Get-MMCompMgmt {

    <#
    .SYNOPSIS
    Opens remote computer management.

    .LINK
    https://github.com/SpacezCowboy/Scripts/blob/master/PowerShell/Profiles-Modules/Profiles/Microsoft.PowerShell_profile.ps1

    .EXAMPLE
    Get-MMCompMgmt -Computer PCNAME
    Opens remote computer management to PCNAME
    #>

    [CmdletBinding()]
    Param ([Parameter(Mandatory = $true)]$computer)

    compmgmt.msc /computer:$computer
}

Function Get-MMPasswordExpiry{

    <#
    .SYNOPSIS
    Searches Ad for a name or Username and returns password set date and expiry.

    .DESCRIPTION
    Searches Ad for a name or Username and returns password set date and expiry. Accepts either a Name (-N) or SAM (-S).

    .EXAMPLE
    Get-MMPasswordExpiry -Name john
    Searches for users based on first name john

    .EXAMPLE
    Get-MMPasswordExpiry -SAM jsmith
    Searches for users based on username jsmith
    #>

    [cmdletbinding()]
    param ([String]$Name,[String]$SAM)

    process {

        If($Name){
            $NameResults = Get-ADUser -filter ("name -like ""*$name*""") -properties passwordlastset, passwordneverexpires, LockedOut, SamAccountName | sort-object name | Format-Table SamAccountName, Name, passwordlastset, Passwordneverexpires, LockedOut
            $NameResults
        }Elseif($SAM){
            Try{
                $Exist = $(try {Get-ADUser $SAM} Catch {$null})
                If ($Null -ne $Exist){
                    Write-Host
                    Write-Host "User found in AD" -ForegroundColor Green
                    Write-Host
                    $SAMResults = Get-ADUser -identity $SAM -properties passwordlastset, passwordneverexpires, LockedOut, SamAccountName | sort-object name | Format-Table SamAccountName, Name, passwordlastset, Passwordneverexpires, LockedOut
                    $SAMResults
                } Else {
                    Write-Host
                    Write-Host "User does not exist in AD" -ForegroundColor Red
                    Write-Host
                }
            }Catch{
                Write-Host "An Error has occured while searching for that username. Please check the username and try again." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        }Else{
            Write-host "No valid input"
        }
    }
}

Function Remove-MMUser{

    <#
    .SYNOPSIS
    Removes user from AD and Exchange.

    .DESCRIPTION
    Removes user from AD and Exchange.

    .NOTES
    Created By: JBrummans
    Original Creation Date: 17/07/2017
    UNTESTED! lots of things to fix
    #>

    [cmdletbinding()]
    param ([String]$Username)

    process {

        Write-host "USER TERMINATION SCRIPT" -ForegroundColor Green
        Write-host

        Write-host "STOP!! Untested function. Will probably error and not complete. Do not run unless for testing." -ForegroundColor Red

        If(!$Username){
            $Username = Read-host "Enter a Username"
            Write-host
        }Else{
            #Nothing
        }

        $UserDetails, $ADMember = Get-MMUserAccountDetails $Username -Return

        #Show user details to confirm correct user
        Write-host "The user " -nonewline
        Write-host $ADMember.CN -nonewline -ForegroundColor Yellow
        Write-host ". Job title "  -nonewline
        Write-host $ADMember.title ", " $Department -nonewline -ForegroundColor Yellow
        Write-host " within deparment "  -nonewline
        Write-host $ADMember.Department -nonewline -ForegroundColor Yellow
        Write-host " will have their memberships removed and account moved to disabled users OU."  -nonewline
        Write-host

        #Create file path
        $Date = Get-MMTimeStamp #Get-Date -Format yyyy_MM_dd_HH_mm
        $File = $Username+"_"+$Date+"_Termination_Report.txt"
        $Path = "C:\Temp\"
        $FullPath = $Path+$File
        Write-Host "Report will be saved to:" $FullPath
        write-Host

        #Writting info to file
        Add-Content -path $FullPath -value $UserDetails
        Add-Content -path $FullPath -value $ADMember

        #Writting file back to terminal as proof
        Get-Content $FullPath 

        Write-host ""
        write-host "Copy the above info into ticket before continuing" -ForegroundColor Yellow
        write-host ""

        #Final warning. BIG WARNING MESSAGE HERE!!!
        Write-host "WARNING!" -ForegroundColor red -Backgroundcolor yellow
        Write-host "Proceeding will remove details from user, disable the account, move to the Disabled Users OU and hide email from address list" -ForegroundColor red
        $ans = read-host "Are you certain you want to proceed? Y or N"
        If($ans -eq "Y"){
            Write-host "Proceeding" -ForegroundColor Green
        }Else{
            Exit-MMFunction -Message1 "Exiting" -Colour1 "Red"
        }
        Write-host

        #Clear properties from user
        Write-host "Clearing users properties (Phones etc)"
        Try{
        Set-ADUser $Username -clear telephoneNumber, MobilePhone #etc etc add more later, also add try/Catch
        }Catch{
            Write-Host "Error! Unable to clear some user properties." -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
        }
        Write-host

        #Remove groups from user. Source: <https://technet.microsoft.com/en-us/library/dd378944(v=ws.10).aspx>
        Write-host "Removing user from groups"
        Get-ADPrincipalGroupMembership -Identity $Username | Where-Object {$_.Name -notlike "Domain Users"} | ForEach-Object {Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $_ -Confirm:$false}

        #Disable user
        Write-host "Disabeling account"
        Disable-ADAccount -Identity $Username

        #Move to disabled OU
        Write-host "Moving user to Disabled Users OU"
        Move-ADObject -Identity $Username -TargetPath "OU=Disabled User Accounts,DC=rcl,DC=domain"

        #Create Exchange Session
        Write-Host "Connecting to Exchange Server..."
        Start-MMExchange -URI EXCHANGESERVER

        #Hide email account from address list.
        Try{
            Set-Mailbox -Identity $mail -HiddenFromAddressListsEnabled $true #add try Catch
            Write-Host "Email has been hidden from Global Access List"
        }Catch{
            Write-Host "Error! Failed to hide mailbox from Exchange" -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
        }
        Remove-PSSession $ExSession #Close the session.

        Write-host "Script completed" -foregroundcolor Green
        Write-Host "Reminder: Report has been saved to:" $FullPath
    }
}

Function Get-MMUserAccountDetails{

    <#
    .SYNOPSIS
    Collects Info about a specified user and displays or returns output.

    .DESCRIPTION
    Collects Info about a specified user and displays or returns output.

    .EXAMPLE
    Get-MMUserAccountDetails USERNAME
    Retrieves user details and displays in an easy to read format.

    .EXAMPLE
    Get-MMUserAccountDetails USERNAME -Return
    Retrieves user details and passes the details back as variables $UserDetails and $admember. Does not display an output.
    #>

    [cmdletbinding()]
    param ([string]$Username, [Switch]$Return)
    Process{

        If(!$Username){
            Write-host "No Username provided. You can bypass this message by entering a username when calling the function." -ForegroundColor red
            $Username = Read-Host "Please enter a Username"
        }
        #Get details to record
        Try{
            $UserDetails = get-aduser $Username -properties * | Select-Object CN, CanonicalName, Title, Office, mail, LastLogonDate, created, Department, telephoneNumber, manager, HomeDirectory
        }Catch{
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            Exit-MMFunction -Message1 "Error has occured. Username may not be valid." -Colour1 "Red" -Message2 "Function will now exit." -Colour2 "Yellow"
        }

        #AD membership to record
        $admember = (Get-ADPrincipalGroupMembership $Username | Select-Object name).name

        If($Return){
            Return $UserDetails, $admember
        }Else{
            $UserDetails

            Write-Host ""
            Write-Host "AD Membership:"
            Write-Host ""

            foreach($adname in $admember){
                Write-Host $adname
            }
        }
    }
}

Function Get-MMPublicIP {

    <#
    .SYNOPSIS
    IP Lookup Tool
      
    .DESCRIPTION
    Returns WhoIS public IP info for your location or an specified public IP

    .NOTES
    Original creator: By Taylor Lee

    .LINK
    https://github.com/SpacezCowboy/Scripts/blob/master/PowerShell/Profiles-Modules/Profiles/Microsoft.PowerShell_profile.ps1
     
    .EXAMPLE
    Get-PublicIP
    Returns your Public IP Info

    .EXAMPLE
    Get-PublicIP -IP 8.8.8.8
    Returns Public IP Info for Google
    #>

    [CmdletBinding()]   
    Param ([String]$IP)

    $ipinfo = Invoke-RestMethod http://ipinfo.io/$IP 
    $PublicIP = @{
        IP       = $ipinfo.ip 
        Hostname = $ipinfo.hostname 
        City     = $ipinfo.city 
        Region   = $ipinfo.region 
        Country  = $ipinfo.country 
        Loc      = $ipinfo.loc 
        Org      = $ipinfo.org
        Phone    = $ipinfo.phone
    } 
    Return $PublicIP
}

Function Remove-MMCharacter{

    <#
    .SYNOPSIS
    Removes a single character from an object and replaces with another.

    .DESCRIPTION
    Removes a single character from an object and replaces with another. If no replacement is given, assumes blank "".
    Outputs to C:\temp\outputfile.txt

    .EXAMPLE
    Remove-MMCharacter C:\temp\content.txt / \
    Reads file content.txt and replaces "/" with "\". Writes file to C:\temp\outputfile.txt
    #>

    [cmdletbinding()]
    param ([Object]$Object, [string]$Character, [String]$replacement="")

    Process{
        Try{
            Get-Content $Object | ForEach-Object {$_ -replace $Character, $replacement}  | Set-Content "C:\temp\outputfile.txt"
            Write-Host "Success!" -ForegroundColor Green
            Write-Host "File Written to: C:\temp\outputfile.txt"
        } Catch{
            Write-Host "Error has occured!" -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
        }
    }
}

Function Out-MMTune {
 
    <#
    .SYNOPSIS
    Plays short tunes depending on success or failure

    .EXAMPLE
    TBA
    #>

    [cmdletbinding()]
    param ([switch]$Success, [switch]$Fail, [switch]$Mario)

    process {

        If($Success){
            [Console]::Beep(500, 100)
            Start-Sleep 0.1
            [Console]::Beep(300, 100)
            Start-Sleep 0.1
            [Console]::Beep(700, 300)

        }Elseif($Fail){
            [Console]::Beep(700, 100)
            Start-Sleep 0.1
            [Console]::Beep(500, 100)
            Start-Sleep 0.1
            [Console]::Beep(300, 300)

        }Elseif($Mario){

            # https://www.reddit.com/r/usefulscripts/comments/3u6ba4/powershell_bash_make_the_pc_speaker_beep_the/

            [Console]::Beep(130, 100)
            [Console]::Beep(262, 100)
            [Console]::Beep(330, 100)
            [Console]::Beep(392, 100)
            [Console]::Beep(523, 100)
            [Console]::Beep(660, 100)
            [Console]::Beep(784, 300)
            [Console]::Beep(660, 300)
            [Console]::Beep(146, 100)
            [Console]::Beep(262, 100)
            [Console]::Beep(311, 100)
            [Console]::Beep(415, 100)
            [Console]::Beep(523, 100)
            [Console]::Beep(622, 100)
            [Console]::Beep(831, 300)
            [Console]::Beep(622, 300)
            [Console]::Beep(155, 100)
            [Console]::Beep(294, 100)
            [Console]::Beep(349, 100)
            [Console]::Beep(466, 100)
            [Console]::Beep(588, 100)
            [Console]::Beep(699, 100)
            [Console]::Beep(933, 300)
            [Console]::Beep(933, 100)
            [Console]::Beep(933, 100)
            [Console]::Beep(933, 100)
            [Console]::Beep(1047, 400)

        } Else {
            #nothing
        }
    }
}

Function Start-MMExchange {
    
    <#
    .SYNOPSIS
    Starts a session with Exchange

    .LINK
    https://practical365.com/exchange-server/powershell-function-to-connect-to-exchange-on-premises/

    .EXAMPLE
    Start-MMExchange
    start session with default server

    .EXAMPLE
    Start-MMExchange -URI SERVERADDRESS
    start session with another server.
    #>

    [cmdletbinding()]
    param ([string]$URI="EXCHANGESERVERNAME")

    process {
        $Credentials = Get-Credential -Message "Enter your Exchange admin credentials"
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$URI/PowerShell/ -Authentication Kerberos -Credential $Credentials
        Import-PSSession $Session
    }
}

Function Get-MMLocalAdminPassword {

    <#
    .SYNOPSIS 
    Gets the local admin password of a workstation.

    .EXAMPLE
    Get-MMLocalAdminPassword
    Prompts for computer name and gets the local admin password.

    .EXAMPLE
    Get-MMLocalAdminPassword -c COMPUTERNAME
    Gets the local admin password of the specified computer.
    #>

    [cmdletbinding()]
    param ([String]$ComputerName = $Null) #Paramaters

    process {
        If(!$ComputerName){
            Write-Host "Computer name not entered. Enter computer name below or pass -c followed by the computer name when calling the function."
            $ComputerName = Read-Host "Enter computer name"
        }
        Try{
            $LocalAdmin = Get-ADComputer $ComputerName -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty ms-Mcs-AdmPwd
            Write-Host "Local admin password for" $ComputerName "is: " -NoNewline
            Write-Host $LocalAdmin -ForegroundColor Yellow
        }Catch{
            #Write-Host "Error has occured. Check connection to AD."
        }

    }
}

Function Get-MMBitLockerRecovery {

    <#
    .SYNOPSIS
    Retrive the Bitlocker Recovery password from AD for a specified computer.

    .DESCRIPTION
    Accepts a -computername paramater. Will then query the domain for this computers Bitlocker recovery password and display it.
    #>

    param ([String]$ComputerName)

    Process{
        If(!$ComputerName){
            $ComputerName = Read-Host "Computer Name required:"
        }
        Try{
            $Computer = Get-ADComputer -Filter {Name -eq $ComputerName}
            $BitLockerRecoveryKey = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $Computer.DistinguishedName -Properties 'msFVE-RecoveryPassword'
            Write-Host "Recovery Key Found" -ForegroundColor Green
            Write-Host "Bitlocker Recovery Key:" -NoNewline
            Write-Host  $BitLockerRecoveryKey.'msFVE-RecoveryPassword' -ForegroundColor Yellow
        }Catch{
            Write-Host "An Error has occured. Check requirments and ensure connection to AD is available." -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
        }
        If($null -eq $Computer){
            Write-Host "No recovery key exists" -ForegroundColor Red
        }
    }
}

Function Set-MMLocalAdmin {

    <#
    .SYNOPSIS
    Add or Remove a user as local admin on a remote computer.

    .LINK
    https://4sysops.com/archives/add-a-user-to-the-local-administrators-group-on-a-remote-computer/

    .EXAMPLE
    Set-LocalAdmin -User USERNAME -Computer COMPUTERNAME
    Adds a user as local admin on a specified computer.

    .EXAMPLE
    Set-LocalAdmin -User USERNAME -Computer COMPUTERNAME -Remove
    Removes a user from local admin group on a specified computer.

    .EXAMPLE
    Set-LocalAdmin
    Prompts to enter Username and Computer name then adds the user to local admin on specified computer.
    #>

    [cmdletbinding()]
    param ([String]$UserName,[String]$ComputerName,[String]$DomainName = "RCL",[switch]$Remove)

    process{
        If(!$ComputerName){
            $ComputerName = Read-Host "Enter Computer name"
        }
        If(!$UserName){
            $UserName = Read-Host "Enter User name"
        }
        $AdminGroup = [ADSI]"WinNT://$ComputerName/Administrators,group"
        $User = [ADSI]"WinNT://$DomainName/$UserName,user"

        Try{
            If($Remove){
                $AdminGroup.Remove($User.Path)
                Write-Host "Success. User" $UserName "has been removed from local admin on" $ComputerName -ForegroundColor Green
            }Else{
                $AdminGroup.Add($User.Path)
                Write-Host "Success. User" $UserName "has been added as local admin on" $ComputerName -ForegroundColor Green
            }
        }Catch{
            If($_.Exception.Message -Like "*Access is denied*"){
                Write-Host "ERROR! Access to computer was denied. Admin rights on remote computer is required." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }Elseif($_.Exception.Message -Like "*The specified account name is already a member of the group*"){
                Write-Host "ERROR! User is already in the Local Admin Group." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }Elseif($_.Exception.Message -Like "*The specified account name is not a member of the group*"){
                Write-Host "ERROR! User is not in the Local Admin Group. No user has been removed." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }Else{
            Write-Host "ERROR! The following error has occured!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        }
    }
}

Function Out-MMCPULog {

    <#
    .SYNOPSIS
    Simple function to log CPU utilization and output to txt file
    #>

    $Path = "C:\temp\cpulog.txt"
    Write-host "Script to log CPU utilization. Script will run until session is terminated manually"
    Write-Host "Out File located at" $Path
    While($true){
        $CPU = (Get-WmiObject win32_processor | Select-Object LoadPercentage).loadpercentage
        $Time = Get-MMTimeStamp
        $Output = "Time: " + $Time + ".   CPU Util:" + $CPU
        Write-Host $Output
        $Output | Out-File $Path -Append
        Start-Sleep 5
    }
}

Function Get-MMTimeStamp {

    <#
    .SYNOPSIS
    Generates a timestamp for output to files.

    .DESCRIPTION
    Generates a timestamp for output to files. Variable $TimeStamp is returned in a pre-formated yyyy-MM-dd-HH-mm-tt
    #>

    [cmdletbinding()]
    param ()

    Process{
        $TimeStamp = Get-Date -format yyyyMMdd-HH-mm-ss
        Return $TimeStamp
    }
}

Function Get-MMUserFolderAccess {

    <#
    .SYNOPSIS
    Gets share permissions and finds users with access.

    .DESCRIPTION
    Accepts a UNC path for a share and gets the shares membership. Then finds users part of those AD members. Returns the results.

    .LINK
    https://community.spiceworks.com/topic/367228-list-users-with-access-to-specific-folder?utm_source=copy_paste&utm_campaign=growth
    https://social.microsoft.com/Forums/en-US/3df8cca7-db6e-47c3-bf26-888eb9e94c1d/get-folder-security-and-if-its-set-using-security-groups-list-the-members?forum=Offtopic

    .EXAMPLE
    Get-MMUserFolderAccess -Share \\Server\Share\
    Gets the shares ACL then finds users in those groups. Returns the result.
    #>

    [cmdletbinding()]
    param ([String]$Share) #Paramaters

    process {
        Try{
            $ADGroups = (get-acl $Share).Access | Where-Object IdentityReference -like "RCL\*" | Select-Object IdentityReference, FileSystemRights
        }Catch{
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error" -Display
        }
        $Array = @()

        ForEach($ADGroup in $ADGroups){
            Try{
                $Group = ($ADGroup.identityreference.value).Replace("RCL\","")
                $UserList = (Get-ADGroupMember $Group -Recursive).Name

                $Array += [PSCustomObject]@{
                    Group = $ADGroup.identityreference
                    Access = $ADGroup.FileSystemRights
                    Users = $Userlist
                }

            }Catch{
                If($_.Exception.Message -Like "*Cannot find an object with identity*"){
                    $Array += [PSCustomObject]@{
                        Group = ""
                        Access = $ADGroup.FileSystemRights
                        Users = $Group
                    }
                } Else {
                Write-Host "ERROR! The following error has occured!" -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error" -Display
                }
            }
        }
        Return $Array
    }
}

Function Show-MMUserFolderAccess {

    <#
    .SYNOPSIS
    Shows share permissions and finds users with access. Displays the results in a readable format.

    .DESCRIPTION
    Accepts a UNC path for a share and get the shares membership. Then finds users part of those AD members. Lists the results.

    .LINK
    https://community.spiceworks.com/topic/367228-list-users-with-access-to-specific-folder?utm_source=copy_paste&utm_campaign=growth
    https://social.microsoft.com/Forums/en-US/3df8cca7-db6e-47c3-bf26-888eb9e94c1d/get-folder-security-and-if-its-set-using-security-groups-list-the-members?forum=Offtopic

    .EXAMPLE
    Show-MMUserFolderAccess -Share \\Server\Share\
    Shows the shares ACL and users in those groups.
    #>

    [cmdletbinding()]
    param ([String]$Share)

    process {
        If(!$Share){
            $Share = Read-Host "Enter Share UNC path (EG. \\Server\Share\)"
        }
        $Results = Get-MMUserFolderAccess $Share

        $DirectUsers = @()

        ForEach($ADGroup in $Results){
            If($ADgroup.Group -eq ""){
                $DirectUsers += $ADgroup.Users + " has " + $ADGroup.Access
            }Else{
                Write-Host "Users in AD Group '"$ADgroup.Group"' have" $ADGroup.Access -ForegroundColor Green
                $ADgroup.Users
            }
        }
        Write-Host "The below users have access directly applied to the folder:" -ForegroundColor Green
        $DirectUsers
    }
}   

Function Get-MMExchangeMobileDevices {

    <#
    .SYNOPSIS
    Gets a users mobile devices which have synced with Exchange.

    .LINK
    https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-2010/aa997974(v=exchg.141)

    .EXAMPLE
    Get-MMExchangeMobileDevices -Username USERNAME
    Searches exchange for the specified user and pulls their mobile device info.
    #>

    [cmdletbinding()]
    param ([String]$username) #Paramaters

    process {
        $Session = Connect-MMExchange
        Import-PSSession -Session $Session -AllowClobber -CommandName Get-MobileDeviceStatistics #Start the session.
        $DeviceList = Get-MobileDeviceStatistics -Mailbox $Username
        Write-Host "Users mobile devices listed below:" -ForegroundColor Yellow
        $DeviceList | Select-Object DeviceType, DeviceFriendlyName, DeviceModel, DeviceOS, DeviceOSLanguage, DeviceUserAgent, FirstSyncTime, LastSuccessSync, DeviceID, Status
    }
}

Function Add-MMAutoLogin {

    <#
    .SYNOPSIS
    Setup autologin for remote machine.

    .LINK
    http://vcloud-lab.com/entries/powershell/microsoft-powershell-remotely-write-edit-modify-new-registry-key-and-data-value
    https://www.preview.powershellgallery.com/packages/Beaver/1.4.5/Content/Beaver.psm1
    #>

    [cmdletbinding()]
    param ([String]$ComputerName,[String]$UserName,[SecureString]$Password, [String]$Domain) #Paramaters

    process {

        Write-host "This function will add registry keys to a remote machine enable auto login."
        $ans = read-host "Continue? Y or N"
        If($ans -eq "Y" -or "y"){
            Write-RegistryValue -ComputerName $ComputerName -RegistryHive LocalMachine -RegistryKeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -ValueName 'AutoAdminLogon' -ValueData 1 -ValueType DWord
            #Write-RegistryValue -ComputerName $ComputerName -RegistryHive LocalMachine -RegistryKeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -ValueName 'AutoLogonCount' -ValueData 2 -ValueType DWord
            Write-RegistryValue -ComputerName $ComputerName -RegistryHive LocalMachine -RegistryKeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -ValueName 'DefaultPassword' -ValueData $Password -ValueType String
            Write-RegistryValue -ComputerName $ComputerName -RegistryHive LocalMachine -RegistryKeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -ValueName 'DefaultUserName' -ValueData $UserName -ValueType String
            Write-RegistryValue -ComputerName $ComputerName -RegistryHive LocalMachine -RegistryKeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' -ValueName 'DefaultDomainName' -ValueData $Domain -ValueType String
    
            Write-Host "Completed" -ForegroundColor Green
        }Else{
            Write-Host "No changes made"
        }
    }
}

Function Write-RegistryValue {

    <#
    .SYNOPSIS
    Writes a reg key to a remote machine.

    .DESCRIPTION
    Sourced from the below link with formatting changes.

    .LINK
    http://vcloud-lab.com/entries/powershell/microsoft-powershell-remotely-write-edit-modify-new-registry-key-and-data-value
    #>

    [CmdletBinding(
        ConfirmImpact='Medium',
        HelpURI='http://vcloud-lab.com',
        DefaultParameterSetName='NewValue')]
        Param ( 
            [parameter(ParameterSetName = 'NewValue', Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [parameter(ParameterSetName = 'NewKey', Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [alias('C')]
            [String[]]$ComputerName = '.',
    
            [Parameter(ParameterSetName = 'NewValue', Position=1, Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
            [parameter(ParameterSetName = 'NewKey', Position=1, ValueFromPipelineByPropertyName=$True)]
            [alias('Hive')]
            [ValidateSet('ClassesRoot', 'CurrentUser', 'LocalMachine', 'Users', 'CurrentConfig')]
            [String]$RegistryHive = 'LocalMachine',
    
            [Parameter(ParameterSetName = 'NewValue', Position=2, Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
            [parameter(ParameterSetName = 'NewKey', Position=2, ValueFromPipelineByPropertyName=$True)]
            [alias('ParentKeypath')]
            [String]$RegistryKeyPath = 'SYSTEM\CurrentControlSet\Software',
    
            [parameter(ParameterSetName = 'NewKey',Position=3, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
            [String]$ChildKey = 'TestKey',
        
            [parameter(ParameterSetName = 'NewValue',Position=4, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
            [alias('Type')]
            [ValidateSet('String', 'Binary', 'DWord', 'QWord', 'MultiString', 'ExpandString')]
            [String]$ValueType = 'DWORD',
    
            [parameter(ParameterSetName = 'NewValue',Position=5, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
            [String]$ValueName = 'ValueName',
    
            [parameter(ParameterSetName = 'NewValue',Position=6, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
            [String]$ValueData = 'ValueData'
        )
        Begin {
            $RegistryRoot= "[{0}]::{1}" -f 'Microsoft.Win32.RegistryHive', $RegistryHive
            Try {
                $RegistryHive = Invoke-Expression $RegistryRoot -ErrorAction Stop
            }
            Catch {
                Write-Host "Incorrect Registry Hive mentioned, $RegistryHive does not exist" 
            }
        }
        Process {
            Foreach ($Computer in $ComputerName) {
                if (Test-Connection $Computer -Count 2 -Quiet) {
                    Try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computer)
                        $key = $reg.OpenSubKey($RegistryKeyPath, $true)
                    }
                    Catch {
                        Write-Host "Check access on computer name $Computer, cannot connect registry" -BackgroundColor DarkRed
                        Continue
                    }
                    switch ($PsCmdlet.ParameterSetName) {
                        'NewValue' {
                            $ValueType = [Microsoft.Win32.RegistryValueKind]::$ValueType
                            $key.SetValue($ValueName,$ValueData,$ValueType)
                            #$Data = $key.GetValue($ValueName)
                            $Obj = New-Object psobject
                            $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $Computer
                            $Obj | Add-Member -Name RegistryPath -MemberType NoteProperty -Value "$RegistryKeyPath"
                            $Obj | Add-Member -Name RegistryValueName -MemberType NoteProperty -Value $ValueName
                            $Obj | Add-Member -Name RegistryValueData -MemberType NoteProperty -Value $ValueData
                            $Obj
                            break
                        }
                        'NewKey' {
                            Try {
                                if ($key.GetSubKeyNames() -contains $ChildKey) {
                                    $Obj = New-Object psobject
                                    $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $Computer
                                    $Obj | Add-Member -Name RegistryPath -MemberType NoteProperty -Value $RegistryKeyPath
                                    $Obj | Add-Member -Name RegistryChildKey -MemberType NoteProperty -Value $Childkey
                                    $Obj
                                    Continue
                                }
                                [void]$Key.CreateSubKey("$ChildKey")
                            }
                            Catch {
                                Write-Host "Not able to create $ChildKey on remote computer name $Computer" -BackgroundColor DarkRed
                                Continue
                            }
                            break
                        }
                    }
                }
                Else {
                    Write-Host "Computer Name $Computer not reachable" -BackgroundColor DarkRed
                }
            }
        }
        End {
            #[Microsoft.Win32.RegistryHive]::ClassesRoot
            #[Microsoft.Win32.RegistryHive]::CurrentUser
            #[Microsoft.Win32.RegistryHive]::LocalMachine
            #[Microsoft.Win32.RegistryHive]::Users
            #[Microsoft.Win32.RegistryHive]::CurrentConfig
        }

        #Write-RegistryValue -ComputerName server01, Member01, test, 192.168.33.11, 192.168.33.12, server01 -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\DemoKey -ChildKey test
        #Write-RegistryValue -ComputerName server01, Member01, test -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\DemoKey -ValueName 'Start' -ValueData 10 -ValueType DWord
    }

Function Test-MMPrimarySitesWan {

    <#
    .SYNOPSIS
    Checks primary sites WAN is pingable
    #>
    
    [cmdletbinding()]
    param ([String]$user,[switch]$repeat) #Paramaters
    
    process {

        # List of server to be tested
        $Servers = "Name1","192.168.0.1","192.168.0.2","SERVERNAME","Name2","192.168.0.3","Name3","192.168.0.4"

        # Windows PowerShell Title
        $host.UI.RawUI.WindowTitle = "Test-MMPrimarySitesWan"

        Clear-Host

        # Write the columns names
        write-host " "
        write-host " Hostname" "`t IP Address" "`t Status"
        write-host "========================================"

        # Get cursor position after the table title
        $myScreenPos = $Host.UI.RawUI.CursorPosition

        While($true){
            # Put the cursor back to where it was
            $Host.UI.RawUI.CursorPosition = $myScreenPos

            # Check if the element on Servers array is a host or just a site name
            Foreach ($element in $Servers) {
                If (($element -eq "Name1") -OR ($element -eq "Name2") -OR ($element -eq "Name3")){
                    If ($element -eq "Name1") {
                        write-host "" $element
                    }
                    Else {
                        write-host "" #Places gap in table row
                        write-host "" $element
                    }
                }Else{
                # For each server name on array ping it, gets its ip address and write on table if it is alive or dead
                    $ServerStatus = test-connection -computername $element -quiet -count 2
                    $ip = [System.Net.Dns]::GetHostAddresses($element)
                    If($ServerStatus){
                        Write-host "" $element `t $ip "`t ALIVE" -ForegroundColor green -BackgroundColor black
                    }Else{
                        write-host "" $element `t $ip "`t DEAD " -ForegroundColor red -BackgroundColor black
                    }
                }
            }
            start-sleep 1
        }
    }
}

Function Get-MMLoggedOnUser{
    
    <#
    .SYNOPSIS
    Gets current logged on user

    .EXAMPLE
    Get-MMLoggedOnUser -ComputerName COMPUTERNAME
    Checks specified computer for a logged on user and returns the result
    #>

    [CmdletBinding()]             
    Param(                        
        [Parameter(Mandatory=$true,
                Position=0,                           
                ValueFromPipeline=$true,             
                ValueFromPipelineByPropertyName=$true
        )]
        [String]$ComputerName, [PSCredential]$Credential
    )

    Process{ 

            Try {
                $CurrentUser = (Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object UserName).Username
            } Catch {

            }
            
            Return $CurrentUser
    }
}

Function Resolve-MMNameOrIP{

    <#
    .SYNOPSIS
    Attempts to resolve Name to IP or IP to Name

    .NOTES
    As IP to name resolution is based of DNS there is a chance the name can resolve incorrectly.

    .EXAMPLE
    Resolve-MMNameOrIP -ComputerName COMPUTERNAME
    Attempts to resovle name to IP address via DNS query and return the result.

    .EXAMPLE
    Resolve-MMNameOrIP -IPAddress 192.168.0.1
    Attempts to resovle IP address to name via DNS query and return the result.
    #>

    [cmdletbinding()]
    param ([String]$ComputerName,[String]$IPAddress) #Paramaters

    Process{
        If($ComputerName){
            Try{
                $IPAddress = (Resolve-DnsName $ComputerName -Type A).ipaddress | select-object -first 1
                Return $IPAddress
            } Catch {
                Write-Host "Error! Unable to resolve IP address from hostname. Check hostname is valid and try again." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        }Elseif($IPAddress){
            Try{
                $ComputerName = [System.Net.Dns]::GetHostByAddress($ipAddress).Hostname
                Return $ComputerName
            } Catch {
                Write-Host "Error! Unable to resolve Hostname to IP address. Check IP Address and try again." -ForegroundColor Red
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        } Else {
            Write-Host "Error! You must provide a valid Hostname or IPAddress" -ForegroundColor Red
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
        }
    }

}

Function Get-MMComputerLocation-OLD {

    <#
    .SYNOPSIS
    Searches for and gets information regarding a computer to assist in locating the computer and possibly the primary user.

    .EXAMPLE
    Get-MMComputerLocation -ComputerName COMPUTERNAME
    Matches the ComputerName to IP address then attempts to find information about the computer which may help identify its location.
    #>

    [cmdletbinding()]
    param ([String]$ComputerName,[String]$IPAddress) #Paramaters

    process {

        If($ComputerName){
            $IpAddress = Resolve-MMNameOrIP -ComputerName $ComputerName
        }Elseif($IPAddress){
            $ComputerName = Resolve-MMNameOrIP -IPAddress $IPAddress
        }

        If (Test-Connection $IPAddress){
            #Get Logged on user
            $CurrentUser = Get-MMLoggedOnUser -ComputerName $ComputerName
            If ($Null -eq $CurrentUser){
                $CurrentUser = "No logged in users"
            }

            #Get list of users who have logged in before.
            $UserProfile = (Get-ChildItem \\$ComputerName\C$\users\).Name

            #Get additional Network info
            $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $ComputerName
            $DefaultGateway = $Networks.DefaultIPGateway
            $DNSServers  = $Networks.DNSServerSearchOrder
            If($networks.DHCPEnabled) {
                $IsDHCPEnabled = $true
            } Else {
                $IsDHCPEnabled = $false
            }

            $DNSServerNames = @()

            ForEach($DNS in $DNSServers){
                Try{
                    $DNSServerNames += [System.Net.Dns]::GetHostByAddress($DNS).Hostname
                }Catch{
                    $DNSServerNames += "NA"
                }
            }
            }Else{
                Exit-MMFunction -Message1 "Error: Failed to connect to computer" -Colour1 "Red"
            }

        $ComputerLocation = New-Object -TypeName psobject
        
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name CurrentUser -Value $CurrentUser
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name UserProfile -Value $UserProfile
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name DefaultGateway -Value $DefaultGateway
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers
        $ComputerLocation | Add-Member -MemberType NoteProperty -Name DNSServerNames -Value $DNSServerNames

        Return $ComputerLocation
    }
}

Function Get-MMDHCPServers {

    <#
    .SYNOPSIS
    Returns list of DHCP servers in the domain.

    .NOTES
    Requires DHCP AD group to be assigned.
    https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc737716(v=ws.10)

    .EXAMPLE
    Get-MMDHCPServers
    Returns full list of DHCP servers and their IP addresses

    .EXAMPLE
    Get-MMDHCPServers -IPAddress *192.168.* -DNSName *SV*
    Returns list of DHCP servers and IP addresses which has "192.168." within the ip address and "SV" within the name.
    #>

    [cmdletbinding()]
    param ([String]$IPAddress = "*",[string]$DNSName = "*") #Paramaters

    process {
        $DHCPServers = Get-dhcpserverindc | Where-Object IPAddress -Like $IPAddress | Where-Object DnsName -Like $DNSName

        Return $DHCPServers

    }
}

Function Get-MMDHCPServerScopes {

    <#
    .SYNOPSIS
    Returns a list of DHCP servers and DHCP scopes on each server.

    .EXAMPLE
    Get-MMDHCPServerScopes
    Returns full list of DHCP servers, their scope and ranges of IP addresses

    .EXAMPLE
    Get-MMDHCPServerScopes -IPAddress *192.168.* -DNSName *SV*
    Returns list of DHCP servers, their scope and ranges of IP addresses where the IP Address of the server starts with 192.168 and has "SV" in the name.
    #>

    [cmdletbinding()]
    param ([String]$IPAddress = "*",[string]$DNSName = "*") #Paramaters

    process {
        $DHCPServers = Get-MMDHCPServers -IPAddress $IPAddress -DNSName $DNSName
        ForEach($DHCPServer in $DHCPServers){
            Write-Host $DHCPServer.DnsName "( IP:" $DHCPServer.IPAddress") has the following Scopes:" -ForegroundColor Yellow
            Try{
                Get-DhcpServerv4Scope -ComputerName $DHCPServer.DnsName | Format-Table -AutoSize
            } Catch {
                If($_.Exception.Message -Like "*Failed to enumerate scopes on DHCP server*"){
                    Write-Host "ERROR! Failed to enumerate scopes on DHCP server. Access is denied. Ensure you have the DHCP AD group (DHCP Users) required to read the DHCP scopes." -ForegroundColor Red
                    Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
                }Elseif($_.Exception.Message -Like "*Failed to get version of the DHCP server*"){
                    Write-Host "ERROR! Failed to get version of the DHCP server. Server may be too old (=<2003) or not compatible with powershell." -ForegroundColor Red
                    Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
                }
            }
        }
    }
}

Function Get-MMInstalledSoftware{

    <#
    .Synopsis 
    Get installed software on the local or remote computer. 
    
    .DESCRIPTION 
    Uses the uninstall path to capture installed software. This is safer than using the WMI query, which 
    checks the integrity upon query, and can often reconfigure, or reset application defaults. This 
    function is built to scale, for quick inventory of software across your environment. 
    
    .LINK
    https://www.preview.powershellgallery.com/packages/core/1.5.0/Content/core.psm1
    
    .EXAMPLE 
    $progs = Get-InstalledPrograms
    Returns list of installed programs from the local machine
    
    .EXAMPLE 
    Get-InstalledPrograms | Select-Object -Property DisplayName, Publisher, InstallDate, Version |FT -Auto 
    
    .EXAMPLE 
    $swInventory = Get-InstalledSoftware -ComputerName 'cmp1','cmp2',sys3' -Credential $creds | Group-Object -Property PSComputerName -AsHashTable -AsString; $swInventory['cmp1'] 
    This will return and object, with all listed computer's installed software. This makes it easy to inventory your computers, and verify them later (if you Expot-CliXml, and Compare-Object later). 
    This can scale to very large networks 
    #>

    [CmdLetBinding()]
    Param(
        [ValidateScript({ Test-Connection -ComputerName $_ -Quiet -Count 4 }) ]
        [String[]] $ComputerName,
        
        [System.Management.Automation.Credential()][PSCredential] $Credential
    )
    
    Begin{
        # Baseline our environment 
        #Invoke-VariableBaseLine

        # Debugging for scripts
        $Script:boolDebug = $PSBoundParameters.Debug.IsPresent
        
        # List of required modules for this function
        #$arrayModulesNeeded = ('Core')
        
        # Verify and load required modules
        #Test-ModuleLoaded -RequiredModules $arrayModulesNeeded -Quiet
    }
    
    Process{
        [String] $strScriptBlock = 'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    
        If ($ComputerName){
            If ($ComputerName.Count -gt 1){
                [String] $ComputerName = $ComputerName -join ','  
            }
            Else{
                [String] $ComputerName = $ComputerName[0].ToString()
            }
            $strScriptBlock = '{' + $strScriptBlock + '}'
            [String] $strCommand = 'Invoke-Command -ComputerName {0} -Command {1} -Authentication Kerberos' -f $ComputerName,$strScriptBlock
        
            If($Credential){  
                $strCommand = $strCommand + ' -Credential $Credential' 
            }
        }Else{    
            $strCommand = $strScriptBlock
        }
        $arrayPrograms = Invoke-Expression -Command $strCommand
    
        $arrayPrograms
    }
    End{
        #Clean up the environment
        #Invoke-VariableBaseLine -Clean
    }
}

Function Test-MMPasswordForDomain {

    <#
    .SYNOPSIS
    Tests a provided password against the minimum requirements for password complexity in AD.

    .LINK
    http://www.checkyourlogs.net/?p=38333

    .EXAMPLE
    Test-MMPasswordForDomain -Password Test2018
    Tests the password Test2018 to see if it meets the minimum requirements for AD.
    #>
    
    Param (
        [Parameter(Mandatory=$true)][String]$Pass,
        [Parameter(Mandatory=$false)][string]$SamAccountName = "",
        [Parameter(Mandatory=$false)][string]$DisplayName
    )
    Process{
        $result = $True
        $PasswordPolicy = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)
        
        If ($Pass.Length -lt $PasswordPolicy.MinPasswordLength) {
            $result = $false
        }
        if (($SamAccountName) -and ($Pass -match "$SamAccountName")) {
            $result = $false
        }
        if ($DisplayName) {
            $tokens = $DisplayName.Split(",.-,_ #`t")
            foreach ($token in $tokens) {
                if (($token) -and ($Pass -match "$token")) {
                    $result = $false
                }
            }
        }
        if ($PasswordPolicy.ComplexityEnabled -eq $true) {
            If ( ($Pass -cmatch "[A-Z]") -and ($Pass -cmatch "[a-z]") -and (($Pass -cmatch "[0-9]") -or ($Pass -cmatch "[^a-zA-Z0-9]")) ) { 
                #do nothing
            } Else {
                $result = $false
            }
        } Else {
            $result = $false
            }
        If($result){
            Write-Host "Password meets minimum complexity" -ForegroundColor Green
        }Else{
            Write-Host "Password does NOT meets minimum complexity" $result -ForegroundColor Red
        }
    }
}

Function Test-MMHaveIBeenPwned{

    <#
    .SYNOPSIS 
    Gets information on compromised email accounts 
    
    .DESCRIPTION
    Gets Pwnage information from https://haveibeenpwned.com 
    Check to see if your email account was involved in a data breach. Returns $False if the email address is not involved in any breach. 
    
    .Example
    HaveIBeenPwned -Email myemailaddress@example.com 
    
    .INPUTS 
    Requires email address 
    
    .OUTPUTS 
    Results are returned as an array 
    
    .LINK
    https://www.powershellgallery.com/packages/Get-EmailPwnage/1.0

    .NOTES 
    Author: Tim Jardim 
    Date: 20.11.18 (dd.mm.yy)
    #>

    [cmdletbinding()]
    param ([String]$Email) #Paramaters

    Process{

        Try{
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 #had to add this as it was reporting an ssl/tls error. This forces tls1.2
            $HaveIBeenPwned=Invoke-WebRequest -Uri "https://haveibeenpwned.com/api/v2/breachedaccount/$Email" -ErrorAction Stop
        }
        Catch{
            Return $false
        }
        $FinalResults=ConvertFrom-Json -InputObject $HaveIBeenPwned 
        Return $FinalResults
    }
}

Function Restart-MMPowershell {

    <#
    .SYNOPSIS
    Simple function to close and reopen powershell
    #>

    [cmdletbinding()]
    param ()

    process {
        Invoke-Item C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Exit
    }
}

Function Send-MMNetMessage{ 
    
    <#
    .SYNOPSIS
        Sends a message to network computers
    .DESCRIPTION
        Allows the administrator to send a message via a pop-up textbox to multiple computers 
      
    .EXAMPLE
        Send-NetMessage "This is a test of the emergency broadcast system.  This is only a test." 
      
        Sends the message to all users on the local computer. 
      
    .EXAMPLE   
        Send-NetMessage "Updates start in 15 minutes.  Please log off." -Computername testbox01 -Seconds 30 -VerboseMsg -Wait 
      
        Sends a message to all users on Testbox01 asking them to log off.   
        The popup will appear for 30 seconds and will write verbose messages to the console.  
     
    .EXAMPLE 
        ".",$Env:Computername | Send-NetMessage "Fire in the hole!" -Verbose 
         
        Pipes the computernames to Send-NetMessage and sends the message "Fire in the hole!" with verbose output 
         
        VERBOSE: Sending the following message to computers with a 5 delay: Fire in the hole! 
        VERBOSE: Processing . 
        VERBOSE: Processing MyPC01 
        VERBOSE: Message sent. 
         
    .EXAMPLE 
        Get-ADComputer -filter * | Send-NetMessage "Updates are being installed tonight. Please log off at EOD." -Seconds 60 
         
        Queries Active Directory for all computers and then notifies all users on those computers of updates.   
        Notification stays for 60 seconds or until user clicks OK. 
         
    .NOTES   
        Author: Rich Prescott   
        Blog: blog.richprescott.com 
        Twitter: @Rich_Prescott

    .LINK
    https://gallery.technet.microsoft.com/scriptcenter/Send-NetMessage-Net-Send-0459d235
    #> 
     
    Param( 
        [Parameter(Mandatory=$True)] 
        [String]$Message, 
         
        [String]$Session="*", 
         
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)] 
        [Alias("Name")] 
        [String[]]$Computername=$env:computername, 
         
        [Int]$Seconds="5", 
        [Switch]$VerboseMsg, 
        [Switch]$Wait 
        ) 
         
    Begin { 
        Write-Verbose "Sending the following message to computers with a $Seconds second delay: $Message" 
    } 
         
    Process { 
        ForEach ($Computer in $ComputerName) { 
            Write-Verbose "Processing $Computer" 
            $cmd = "msg.exe $Session /Time:$($Seconds)" 
            if ($Computername){$cmd += " /SERVER:$($Computer)"} 
            if ($VerboseMsg){$cmd += " /V"} 
            if ($Wait){$cmd += " /W"} 
            $cmd += " $($Message)" 
            
            Invoke-Expression $cmd 
        } 
    }End{ 
        Write-Verbose "Message sent." 
    } 
}

Function Exit-MMFunction {

    <#
    .SYNOPSIS
    Function to display exit message(s).

    .DESCRIPTION
    Function to display up to three exit message(s) each with a different colour (default colour is white)

    .EXAMPLE
    Exit-MMFunction -Message1 "Function has quit" -Colour1 "red" -Message2 "An error occured" -Colour "blue"
    Displays two messages. First in red second in blue. Then exits.

    .EXAMPLE
    Exit-MMFunction -Message1 $output -Colour1 $colour
    Displays one message. Accepts the variable called $output as the message and $colour as the colour of the message.
    #>

    [cmdletbinding()]
    param ([String]$Message1,[String]$Message2,[String]$Message3,[string]$Colour1 = "White",[string]$Colour2 = "White",[string]$Colour3 = "White") #Paramaters

    process {
        If($Message1){
        Write-Host $Message1 -ForegroundColor $Colour1
        }
        If($Message2){
            Write-Host $Message2 -ForegroundColor $Colour2
        }
        If($Message3){
            Write-Host $Message3 -ForegroundColor $Colour3
        }
        Read-Host -Prompt "Press Enter to exit"
        Exit
    }
}

Function Write-MMLog {

    <#
    .SYNOPSIS
    Creates or appends a log entry to C:\temp\Multi-Module.log

    .DESCRIPTION
    Creates or appends a log entry to C:\temp\Multi-Module.log. Accepts a function name, message and severity. A timestamp is always appended.

    .EXAMPLE
    Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Invalid query run" -Severity "Error"
    Appends the Message "Invalid query run" with the currently running function name and severity as "Error" to the log file C:\temp\Multi-Module.log with a timestamp.
    #>

    [CmdletBinding()]
    Param(
        [Parameter()][string]$Message = "No message was passed to log.",
        [Parameter()][string]$Function = "N/A",
        [Parameter()][ValidateSet('Information','Warning','Error')][string]$Severity = 'Information',
        [Parameter()][Switch]$Display
    )

    Process{
        $Date = Get-MMTimeStamp
        $LogPath = "C:\temp\Multi-Module.log"

        #Test if log exists. If not create it and add headings.
        If((Test-Path $LogPath) -eq $False){
            New-item $LogPath | Out-Null
            Add-Content "Date   :    Severity  :    Function    :   Message" -Path $LogPath
        }

        #Apped entry to log file.
        Add-Content -Value "$Date : $Severity : $Function : $Message" -Path $LogPath

        #Write message back if $Display switch is passed.
        If($Display){
            If($Severity -eq "Error"){Write-Host $Message -ForegroundColor Red}
            Else{Write-Host $Severity ":" $Message -ForegroundColor Yellow}
        }
    }
}

Function Search-MMEmailLog {

    <#
    .SYNOPSIS
    Searches email log for emails sent to or from an email address.

    .DESCRIPTION
    Searches email log for emails sent to or from an email address. By default only searces the last day and limited to 500 results. Both of these values can be increased.

    .EXAMPLE
    Search-MMEmailLog -Send email@email.com.au
    Searches for any emails sent from email@email.com.au, to anyone, within the last day, limited to 500 results.

    .EXAMPLE
    Search-MMEmailLog -Send email@email.com.au -Recipient other@email.com.au -Days 5 -ResultSize 1000
    Searches for any emails sent from email@email.com.au, to other@email.com.au, within the last 5 days, limited to 1000 results.
    #>

    [cmdletbinding()]
    param ([String]$Send="*",[String]$Recipient="*", [int]$Days = 1, [int]$ResultSize = 500)

    process {
        #Search email log and return results.
        $Session = Connect-MMExchange
        Import-PSSession -Session $Session -AllowClobber -CommandName Get-MessageTrackingLog #Start the session.
        If(!$Send.Contains('*')){
            Try{
                $Results = Get-MessageTrackingLog -Server EXCHANGESERVERNAME -ResultSize $ResultSize -Sender $Send -start (get-date).AddDays(-$days) | Where-object Recipients -like $Recipient | Select-Object Sender, Recipients, Timestamp, MessageSubject, Totalbytes, MessageID 
            }Catch{
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        }Elseif(!$Recipient.Contains('*')){
            Try{
                $Results = Get-MessageTrackingLog -Server EXCHANGESERVERNAME -ResultSize $ResultSize -Recipients $Recipient -start (get-date).AddDays(-$days) | Where-object Sender -like $Send | Select-Object Sender, Recipients, Timestamp, MessageSubject, Totalbytes, MessageID 
            }Catch{
                Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error"
            }
        }Else{
            #Write-Host "Error: Either Sender or recipient must not contain wildcards."
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "Invalid query. Either Sender or recipient must not contain wildcards." -Severity "Error" -Display
        }
        Return $Results | Sort-Object Timestamp -Descending
    }
}

Function Set-MMOutOfOffice {

    <#
    .SYNOPSIS
    Sets an out of office notification on a users mailbox.

    .EXAMPLE
    Set-MMOutOfOffice -User JSMITH -IntMsg "Im no longer working here please email Other@company.com.au" -ExtMsg "Im no longer working here. Please call reception on XXXXXXXXXXX"
    Sets an out of office on the user JSMITH's email. Internal replies are defined by paramater -IntMsg and external replies defined by paramater -ExtMsg. 
    Quotation marks are required for the replies.
    #>

    [cmdletbinding()]
    param ([String]$User, [String]$IntMsg, [String]$ExtMsg) #Paramaters

    process {
        $Session = Connect-MMExchange
        Import-PSSession -Session $Session -AllowClobber -CommandName Set-MailboxAutoReplyConfiguration, Get-MailboxAutoReplyConfiguration #Start the session.
        Try{
            Set-MailboxAutoReplyConfiguration -Identity $User -AutoReplyState Enabled -InternalMessage $IntMsg -ExternalMessage $ExtMsg
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message "An Automatic reply has been set for user: $User" -Severity "Information" -Display
        }Catch{
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error" -Display
        }
        
        #Maybe add a check to confirm auto reply has been set?
            #$AutoReply = Get-MailboxAutoReplyConfiguration -identity $User
    }
}

  function Format-TimeSpan {
      <#
      .SYNOPSIS
      Required for Get-MMUptime
      #>
    process {
      "{0:00} d {1:00} h {2:00} m {3:00} s" -f $_.Days,$_.Hours,$_.Minutes,$_.Seconds
    }
  }

  function Get-MMUptime {

    <#
    .SYNOPSIS
    Outputs the last bootup time and uptime for a computer.

    .DESCRIPTION
    Outputs the last bootup time and uptime for a computer. Assuming current user account has access to perform this action on the remote computer.

    .PARAMETER ComputerName
    The local or remote computer name. The default is the current computer. Wildcards are not supported.

    .LINK
    https://gist.github.com/morisy/8aa34f4ba0beaf8eef1b9224c616e041
    
    #>
    [cmdletbinding()]
    Param([String]$ComputerName)
    # In case pipeline input contains ComputerName property
    Process{
        if ( $computerName.ComputerName ) {
            $computerName = $computerName.ComputerName
          }
        If (!$ComputerName){
        $ComputerName = [Net.Dns]::GetHostName()
        }
        $params = @{
            "Class" = "Win32_OperatingSystem"
            "ComputerName" = $computerName
            "Namespace" = "root\CIMV2"
        }
        Try {
        $wmiOS = Get-WmiObject @params -ErrorAction Stop
        } Catch {
            Write-MMLog -Function ($MyInvocation.MyCommand).Name -Message $_.Exception.Message -Severity "Error" -Display
        }
        $LastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($wmiOS.LastBootUpTime)
        $Uptime = (Get-Date) - $LastBootTime | Format-TimeSpan
        Return $Uptime, $LastBootTime
    }
}

Function Test-MMFunction {

    <#
    .SYNOPSIS
    Function Template.

    .LINK
    Link goes here.

    .EXAMPLE
    Example goes here.
    #>

    [cmdletbinding()]
    param ([String]$user,[switch]$Swit) #Paramaters

    process {
        #Code goes here
        Write-Host "This is not the function you are looking for. Move Along."
    }
}
