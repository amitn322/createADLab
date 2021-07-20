<#

.SYNOPSIS
This is a simple powershell script that helps you create an Active Directory Lab.

.DESCRIPTION
The main goal of this script is to ease the task of creating an Active Directory Lab. You can configure all the options in the adConfig.json file in the same directory.

Uninstall: 
Uninstall-addsdomaincontroller
Uninstall-windowsfeature

.EXAMPLE
./configureADLab.ps1

.NOTES
Note that the script will resume automatically after a reboot. 

.LINK
https://www.amitnepal.com





$Secure_String_Pwd = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force


#>

param(
       [switch]$scheduledTask,
       [String]$serverNumber,
	   [string]$step
)

function installAdStuff{
    Install-windowsfeature AD-domain-services
    Install-WindowsFeature RSAT-ADDS
    Import-Module ADDSDeployment
}

function createScheduledTask
{
    param (
    [Parameter()][string]$scriptFile,
	[Parameter()][string]$step
    )

    $scriptFullPath = $PSCommandPath   # $MyInvocation.MyCommand.Path
    $taskName = "Configure DC"

    $action = New-ScheduledTaskAction -Execute "Powershell.exe"  -Argument "-NoExit $scriptFullPath -scheduledTask `$true -step $step -ExecutionPolicy ByPass"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $exists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
    if($exists)
    {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description "DC Configuration Task" 
}

function removeScheduledTask
{
    param ([Parameter()][string]$taskName)
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false 
}

function gatherInfo
{
# for now disabling cli options, only config option available
[CmdletBinding()]
   param(
      #[Parameter(Mandatory = $true)] $serverNumber ,
      #[Parameter(Mandatory = $true)][string] $DomainName ,
      #[Parameter(Mandatory = $true)][string] $hostname,
      #[Parameter(Mandatory = $true)][string] $IPAddress,
      #[Parameter(Mandatory = $true)][string] $MaskBits,
      #[Parameter(Mandatory = $true)][string] $DefaultGateway,
      #[Parameter(Mandatory = $true)][string] $DNSServer,
      #[Parameter(Mandatory = $true)][string] $eaUserName,
      [Parameter(Mandatory = $true)][Security.SecureString]$eaPass, #=$(Throw "Password Required."),
      [Parameter(Mandatory = $true)][Security.SecureString]$AdminPass#=$(Throw "Admin Password Required.")
   )

   $properties=@{
    #ServerNumber = $ServerNumber
    #DomainName=$DomainName
    #hostname=$hostname
    #IPAddress=$IPAddress
    #MaskBits=$MaskBits
    #DefaultGateway=$DefaultGateway
    #DNSServer=$DNSServer
    #eaUserName=$eaUserName
    eaPass=$eaPass 
    AdminPass=$AdminPass

   }

   return  New-Object psobject -Property $properties 
}

function SecureStringToPlainText()
{
    param(
    [SecureString]$secureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $plainTextString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    return $plainTextString
}

function plainTextToSecureString()
{
	param([string] $plainTextString )
	$secureString = ConvertTo-SecureString $plainTextString -AsPlainText -Force	
	return $secureString
}

function getIPAddress()
{
    param([Parameter()][string] $promptMessage)
	 do {
		try {
			$correctInput = $true
			[ipAddress] $ipAddrObj  = Read-Host -Prompt $promptMessage
			}catch{
				$correctInput = $false 
				Write-Host "Invalid Input, try again!"
			}

    }until($correctInput)  
  
  return $ipAddrObj.IPAddressToSTring
}

function createConfigFile
{
    Param([String]$configFileName)

    $dcObject = New-Object psobject 
   
	do {
	try {
		$correctInput = $true
		Write-Host "Up to 3 domain controllers are supported in this version. Primary, Secondary and Child Domain"
		[ValidateRange(1,3)]$totalServers  = Read-Host -Prompt "How many domain Controllers do you want to build ? e.g: 1, 2 or 3:"
		}catch{
			$correctInput = $false 
			Write-Host "Invalid Input, try again!"
		}

	}until($correctInput)
	
    $dcObject | Add-Member -NotePropertyName 'totalServers' -NotePropertyValue $totalServers
    $dcObject | Add-Member -NotePropertyName 'domainName' -NotePropertyValue (Read-Host -Prompt "Enter Domain Name for the DC:")
    $dcObject | Add-Member -NotePropertyName 'domainNetBiosName' -NotePropertyValue (Read-Host -Prompt "Enter NetBios Name for the Domain:")
    $dcObject | Add-Member -NotePropertyName 'dnsServer' -NotePropertyValue (Read-Host -Prompt "Enter DNS Server IP, Please note that DNS Server Must be Set to First DC for other Domain Controllers:")
    $dcObject | Add-Member -NotePropertyName 'defaultGateway' -NotePropertyValue (getIPAddress "Enter Default Gateway IP:")
    $dcObject | Add-Member -NotePropertyName 'maskBits' -NotePropertyValue (Read-Host -Prompt "Enter Subnet Mask Bits eg. 24:")
    $dcObject | Add-Member -NotePropertyName 'eaUserName' -NotePropertyValue (Read-Host -Prompt "Enter Enterprise Admin Username:")
    $dcObject | Add-Member -NotePropertyName 'eaPassword' -NotePropertyValue (SecureStringToPlainText(Read-Host -Prompt "Enter Enterprise Password:" -AsSecureString))
    $dcObject | Add-Member -NotePropertyName 'AdminPassword' -NotePropertyValue (SecureStringToPlainText(Read-Host -Prompt "Enter Administrator Password:" -AsSecureString))
    $dcObject | Add-Member -NotePropertyName 'safeModeAdminPassword' -NotePropertyValue (SecureStringToPlainText(Read-Host -Prompt "Enter SafeMode Admin Password:" -AsSecureString))

   for($i=1;$i -le $totalServers;$i++)
   {
       
        $ipAddress = getIPAddress "Enter DC$i IP Address:"
        $dcHostName = Read-Host -Prompt "Enter DC$i Hostname:"        
        New-Variable -Name "dc$($i)IPAddress" -Value $ipAddress
        $dcObject | Add-Member -NotePropertyName "dc$($i)IPAddress" -NotePropertyValue "$ipAddress"
        New-Variable -Name "dc$($i)HostName" -Value $dcHostName
        $dcObject | Add-Member -NotePropertyName "dc$($i)HostName" -NotePropertyValue "$dcHostName"  
   } 
   
   $dcObject | ConvertTo-Json | Set-Content -Path $configFileName
   Write-Host "Configuration File Created at: $configFileName"
}


function saveState(
    [string]$fileName, [string]$serverNumber, [string]$DomainName, 
    [string]$hostname, [string]$IPAdress, [string]$DefaultGateway, [string]$DNSServer,
    [string]$adminPasswd, [string]$safeModeAdminPasswd, [string]$eaUserName, [string]$eaPasswd)
{
    $state = @{
    'serverNumber' = $serverNumber;
    'DomainName' = $DomainName;
    'hostname' = $hostname; 
    'IPAddress' = $IPAddress;
    'DefaultGateway' = $DefaultGateway;
    'DNSServer' = $DNSServer;
    'adminPasswd' = $adminPasswd;
    'safeModeAdminPasswd' = $safeModeAdminPasswd;
    'eaUserName' = $eaUserName;
    'eaPasswd' = $eaPasswd;
    }; 
   
    $state | ConvertTo-Json | Set-Content -Path $fileName
}

function readState{
param (
    [Parameter()][string]$StateFile
)

    return Get-Content -Path $StateFile | ConvertFrom-Json

}

function configureIPAddress{
   param(

      [Parameter(Mandatory = $true, Position = 0)][string] $DomainName ,
      [Parameter(Mandatory = $true, Position = 1)][string] $IPAddress,
      [Parameter(Mandatory = $true, Position = 2)][string] $MaskBits,
      [Parameter(Mandatory = $true, Position = 3)][string] $DefaultGateway,
      [Parameter(Mandatory = $true, Position = 4)][string] $DNSServer
   )

    $ipAddressType = "IPv4"
    Write-Host "(+)  Configuring Static IP for Domain Controller"
    $maskBits = If($maskBits) { $maskBIts } else {"24"}

    $iface = Get-NetAdapter | ? {$_.Status -eq "up" }
    If (( $iface | Get-NetIPConfiguration).Ipv4DefaultGateway) {
        $iface | Remove-NetIPAddress -AddressFamily $ipAddressType -Confirm:$false
    }
    If (($iface | Get-NetIPConfiguration).Ipv4DefaultGateway) {
     $iface | Remove-NetRoute -AddressFamily $ipAddressType -Confirm:$false
    }

    $iface | New-NetIPAddress -AddressFamily $ipAddressType -IPAddress $ipAddress -PrefixLength $maskBits -DefaultGateway $DefaultGateway 
    if($DNSServer){$iface | Set-DnsClientServerAddress -ServerAddresses $DNSServer}
    Write-Host "(-) IP configuration Complete."
}

function configureDC{
   param(

      [Parameter(Mandatory = $true)][string] $ADNetbiosName ,
      [Parameter(Mandatory = $true)][string] $DomainName,
      [Parameter(Mandatory = $true)][string] $MaskBits,
      [Parameter(Mandatory = $false)][string] $childDomainName,
      [Parameter(Mandatory = $true)][string] $safeModeAdministratorPassword,
      [Parameter(Mandatory = $true)][string] $AdminPassword,
      [Parameter(Mandatory = $true)][string] $serverNumber
   )

	[securestring]$secStringPassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
	[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ("Administrator", $secStringPassword)

	$SafeModeAdministratorPasswordSecString = plainTextToSecureString $safeModeAdministratorPassword
	Get-LocalUser -Name "Administrator" | Set-LocalUser -Password $secStringPassword
   
   switch ( $serverNumber )
    {
        1 { 
            Write-Host "DC 1 Selected "
            Install-ADDSForest -CreateDNSDelegation:$False -DatabasePath “c:\Windows\NTDS” -DomainMode ‘Win2012’ -DomainName $domainName -DomainNetbiosName $ADNetbiosName -ForestMode ‘Win2012’ -InstallDNS:$true -LogPath “C:\Windows\NTDS” -NoRebootOnCompletion:$false -Sysvolpath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $SafeModeAdministratorPasswordSecString
    
          }
        2 { 
            Write-Host "DC2 Selected wohoooooooooo"
            Write-Host "Netbios: " $ADNetbiosName
            
            Install-ADDSDomainController -NoGlobalCatalog:$false -CreateDNSDelegation:$false -Credential $credObject -CriticalReplication:$false -DatabasePath “C:\Windows\NTDS” -DomainName $domainName -InstallDNS:$true -LogPath “C:\Windows\NTDS\Logs” -SiteName “Default-First-Site-Name” -SYSVOLPath “C:\Windows\SYSVOL” -Force:$true -SafeModeAdministratorPassword $SafeModeAdministratorPasswordSecString
    
           }
        3 { 
            Write-Host "DC3 Selected"
            if(!$childDomainName)
            {
                Write-Host "Child Domain Is Required"
                $childDomainName  = Read-Host "Please Enter Child Domain Name:"
            }
            
            Install-ADDSDomain -Credential $credObject -NewDomainName $childDomainName -ParentDomainName $parentDomainName -InstallDNS -CreateDNSDelegation -DomainMode Win2012 -DatabasePath “C:\Windows\NTDS” -SYSVOLPath “C:\Windows\SYSVOL” -LogPath “C:\Windows\NTDS\Logs” -SafeModeAdministratorPassword $SafeModeAdministratorPasswordSecString -Force:$true
         }     
    }
}


# Functions End

# Main Program Start

#####################TODOOOOooooooooo###############################
<#
	- Add option to get configuration parameters form CLI as well as config file. 
	- Encrypt password in the config file. 
	- Potentially generate random passwords and save in log file. 

#>

$Tab = [char]9

$stateFileName = $PSScriptRoot + "\resume.json"
$configFile = $PSScriptRoot + "\adConfig.json"
$useConfig = "True" #only configFile option available for now. 

if (!(Test-Path $configFile))
{
    Write-Warning "Configuration File Doesn't exist, lets create one"
    createConfigFile $configFile
    exit
    
}

$dcObject = New-Object -TypeName psobject 
if(!$serverNumber)
{
    $serverNumber = Read-Host "Please Enter Server Number, Eg. 1, 2 or 3:"
}

#$isScheduledTask = $args[0]
if (!$scheduledTask)
{
    $allArgs = $PsBoundParameters.Values + $args    
     #hmm @PSBoundParameters
    if($useConfig)
    {
            Write-Host "Using Configuration File : $configFile"
            $configData = Get-Content -Path $configFile | ConvertFrom-Json
            Write-Host "Hostname: " $configData.dc2Hostname

            $properties = @{
                'totalServers' = $configData.totalServers
                'DomainName' = $configData.DomainName
                'domainNetBiosName' = $configData.domainNetBiosName;
                'dc1IP' = $configData.dc1IPAddress
                'dc2IP' = $configData.dc2IPAddress
                'dc3IP' = $configData.dc3IPAddress
                'ipAddress' = ""
                'hostname' = ""
                'dc1Hostname' = $configData.dc1Hostname
                'dc2Hostname' = $configData.dc2Hostname
                'dc3Hostname' = $configData.dc3Hostname
                'DNSServer' = $configData.DNSServer
                'DefaultGateway' = $configData.DefaultGateway
                'maskBits' = $configData.maskBits
                'eaUserName' = $configData.eaUserName
                'eaPassEncrypted' = $configData.eaEncryptedPassword
                'eaPassword' = $configData.eaPassword
                'AdminPassEncrypted' = $configData.adminEncryptedPassword
                'AdminPassword' = $configData.adminPassword
                'SafeModeAdminPassword' = $configData.safeModeAdminPassword
                'SafeModeAdminPassEncrypted' = $configData.safeModeAdmiEncryptedPassword
                'ServerNumber' = $serverNumber
                'childDomainName' = $configData.childDomainName
               }    
               $dcObject = New-Object psobject -Property $properties                
    }else
    {
        ## ToDo add option to pass everything on command line.. 
        $allArgs = $PsBoundParameters.Values + $args
        $dcObject = gatherInfo @PSBoundParameters    
        Write-Host " All Args: $allArgs"       
    }

    # prompt for things that we don't have information about yet 
    # todo : create a function and pass the dcobject, and prompt for anything that we don't have yet. 

    if($serverNumber -eq 1) {
        $dcObject.ipAddress = $dcObject.dc1IP
        $dcObject.hostname = $dcObject.dc1Hostname
    }
    if($serverNumber -eq 2) {
        $dcObject.ipAddress = $dcObject.dc2IP
        $dcObject.hostname = $dcObject.dc2Hostname
       
    }
    if($serverNumber -eq 3) {
        $dcObject.ipAddress = $dcObject.dc3IP
        $dcObject.hostname = $dcObject.dc3Hostname
    }

    Write-Host "(-) Using Below Configurations : "
    Write-Host "$Tab Domain Name:  $($dcObject.DomainName)"
    Write-Host "$Tab Domain NetBios Name:  $($dcObject.domainNetBiosName)"
    Write-Host "$Tab HostName:  $($dcObject.hostname)"
    Write-Host "$Tab IP Address:  $($dcObject.ipAddress)"
    Write-Host "$Tab Subnet Mask Bits:  $($dcObject.maskBits)"
    Write-Host "$Tab Default Gateway:  $($dcObject.DefaultGateway)"
    Write-Host "$Tab DNS Server:  $($dcObject.DNSServer)"

    Write-Host "(-) Renaming Server"
    Rename-Computer -NewName $dcObject.hostname -ErrorAction SilentlyContinue
    configureIPAddress $dcObject.DomainName $dcObject.IPAddress $dcObject.maskBits $dcObject.DefaultGateway $dcObject.DNSServer

    $dcObject | ConvertTo-Json | Set-Content -Path $stateFileName
    #just save the dcObject, no need to save below 
    #saveState $stateFileName $ServerNumber $dcObject.DomainName $dcObject.hostname $dcObject.IPAddress $dcObject.DefaultGateway $dcObject.DNSServer $encryptedAdminPasswd $encryptedSafeModeAdminPasswd $eaUserName $encryptedEAPasswd
    createScheduledTask $fileName "configure-dc"
    $cloned = Read-Host "(-) Did you Clone or Copy this Operating System ? (y/n):" 

    if($cloned -eq "y")
    {
        Write-Host "(+) Cloned machine, Running Sysprep, the system will reboot after completion. THe setup will continue automatically after reboot"
        
        $sysprepPath="$env:WINDIR\system32\sysprep\sysprep.exe /generalize /reboot /oobe /quiet"
        iex $sysprepPath 
        Restart-Computer 

    }else
    {
        Write-Host "(+) Rebooting System, The setup should continue automatically after reboot"
        Restart-Computer 
    }

}else
{
    Write-Host "Resuming After Reboot"
    $savedData = Get-Content -Path $stateFileName | ConvertFrom-Json
    Write-Host "Server Number:"  $savedData.serverNumber
    $adminPasswd = $savedData.AdminPassword
    $safeModeAdminPasswd = $savedData.SafeModeAdminPassword
    $eaUserName = $savedData.eaUserName
    $eaPasswd = $savedData.eaPassword
    if($savedData.ServerNumber -lt 1 -and $savedData.ServerNumber -gt $savedData.totalServers)
    {
        Write-Error "Yo Bruh, messing with me ?, I Quit !"
        exit
    }
    <#if($step -eq "install-adstuff")
    {
        Write-Host "(-) Installing AD Tools and Stuff.."
        installAdStuff
    }
	else#>
    if($step -eq "configure-dc")
	{
		Write-Host "(-) Installing AD Tools and Stuff.."
        installAdStuff
        createScheduledTask $fileName "create-users"
		ConfigureDC -ADNetbiosName $savedData.domainNetBiosName -DomainName $savedData.DomainName -MaskBIts $savedData.maskBits -childDomainName $savedData.childDomainName -safeModeAdministratorPassword $savedData.SafeModeAdminPassword -serverNumber $savedData.ServerNumber -AdminPassword $savedData.AdminPassword
		Write-Host "The Server will reboot and rest of the installation process will continue automatically after reboot."
		
	}elseif($step -eq "create-users")
	{
	    Write-Host "(-) Creating Users" 
		[securestring]$secStringPassword = ConvertTo-SecureString $adminPasswd -AsPlainText -Force
        [pscredential]$credObject = New-Object System.Management.Automation.PSCredential ("Administrator", $secStringPassword)
		New-ADUser -Name $eaUserName -AccountPassword(ConvertTo-SecureString $eaPasswd -AsPlainText -Force) -Enabled $true -ChangePasswordAtLogon $false
		Add-ADGroupMember -Identity "Enterprise Admins" -Members $eaUserName	
		removeScheduledTask -TaskName "Configure DC" 
		Write-Host "Active Directory has been configured on this machine. Please run this script with appropriate server number on any other server that you may want to configure. You will only need to change the server number option. "
	
	}
}


