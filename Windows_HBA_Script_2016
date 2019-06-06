'=========================================================='
RECORDING TRANSCRIPT TO DUMP FILE
'=========================================================='
$CurrentDir = $PSScriptRoot
$ServerName = $env:computername
Get-Date -Format G
$DumpFilePath =  "$CurrentDir\"+"output.txt"

'=========================================================='
Checking if your PowerShell Script Execution Policy is set to Unrestricted
'=========================================================='

Start-Transcript -Path $DumpFilePath -NoClobber

Write-Host
Write-Host 'Checking if your PowerShell Script Execution Policy is set to Unrestricted' -ForegroundColor Yellow -BackgroundColor Black
Start-Sleep -s 5
Write-Host
$ExecutionPolicy = Get-ExecutionPolicy
$ScriptExecution = "Unrestricted"
    If ($ExecutionPolicy -eq $ScriptExecution) 
        {
            Write-Host 'Yay! your PowerShell Script Execution Policy is already set to ' $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
        }
    Else
        {
            Write-Host Your PowerShell Script Execution Policy is set to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
            Write-Host
            Write-Host 'This policy should be set to Unrestricted for the script to execute properly.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'This change will be reverted back to its original state after script execution is complete.' -ForegroundColor Magenta -BackgroundColor Black
            Write-Host
            Write-Host 'Setting PowerShell Script Execution Policy to Unrestricted automatically. Please Wait...'
            Start-Sleep -s 5
            
            Set-ExecutionPolicy Unrestricted -force
        
            Write-Host
            Write-Host 'PowerShell Script Execution Policy is now set to Unrestricted.' -ForegroundColor Yellow -BackgroundColor Black
            Start-Sleep -s 5
        }
"`n"

'=========================================================='
Write-Host 1. SERVER DETAILS
'=========================================================='
systeminfo
Get-CimInstance Win32_OperatingSystem | FL * 

'=========================================================='
Write-Host 2. BIOS INFORMATION
'=========================================================='
Get-WmiObject -Class Win32_BIOS | Format-List *

'=========================================================='
Write-Host 3. LOCAL ACCOUNTS INFORMATION / LOCKOUT POLICY
'=========================================================='
net accounts

'=========================================================='
Write-Host 3.1 CURRENT LOGIN USER
'=========================================================='
net user

'=========================================================='
Write-Host 3.2 LOCAL USERS INFORMATION
'=========================================================='
Get-LocalUser | Select-Object *

'=========================================================='
Write-Host 3.3 LOCAL USERS PASSWORD POLICY
'=========================================================='
net user
	
'=========================================================='
Write-Host 3.4 LOCAL GROUP POLICY
'=========================================================='
gpresult /Scope User /v
gpresult /Scope Computer /v

'=========================================================='
Write-Host 4. USER PROFILES
'=========================================================='
Get-CimInstance -ClassName Win32_UserProfile | select -first 1
 
'=========================================================='
Write-Host 5. AUDITING SHOULD BE ENABLED
'=========================================================='
auditpol.exe /get /category:*

'=========================================================='
Write-Host 6. AVAILABLE MODULES
'=========================================================='

Get-Module -ListAvailable

'=========================================================='
Write-Host 7. DISK INFORMATION
'=========================================================='

Get-WmiObject -Query “SELECT * FROM Win32_LogicalDisk”


'=========================================================='
Write-Host  8. EVENT LOGS
'=========================================================='

Get-EventLog -Log "Application" 

'=========================================================='
Write-Host  9. LIST ALL SERVICES
'=========================================================='

Get-Service

	'=========================================================='
	Write-Host  9.1 LIST ALL RUNNING SERVICES
	'=========================================================='
	Get-Service | Where-Object {$_.Status -eq 'Running'}

'=========================================================='
Write-Host 10. INSTALLED SECURITY PATCHES
'=========================================================='
Get-Hotfix

'=========================================================='
Write-Host 11. WIDNOWS FIREWALL BASELINE
'=========================================================='

$Global
$Profiles

'=========================================================='
Write-Host 12. INSTALLED SOFTWARES INFORMATION
'=========================================================='
Get-WmiObject -Class Win32_Product 

'=========================================================='
Write-Host  13. AUDIT INFORMATION
'=========================================================='

auditpol.exe /get /category:*

	Write-Host 13.1 Account Logon
	'======================='

	Auditpol /get /subcategory:"Credential Validation"
	Auditpol /get /subcategory:"Kerberos Authentication Service"
	Auditpol /get /subcategory:"Kerberos Service Ticket Operations"
	Auditpol /get /subcategory:"Other Account Logon Events"


	Write-Host 13.2 ACCOUNT MANAGEMENT
	'======================='

	gets - the entire category - Auditpol /get /category:"Account Management"

	Auditpol /get /subcategory:"Application Group Management"
	Auditpol /get /subcategory:"Computer Account Management"
	Auditpol /get /subcategory:"Distribution Group Management"
	Auditpol /get /subcategory:"Security Group Management"
	Auditpol /get /subcategory:"Other Account Management Events"
	Auditpol /get /subcategory:"User Account Management"


	Write-Host 13.3 Detailed Tracking
	'======================='

	Auditpol /get /subcategory:"Process Termination"
	Auditpol /get /subcategory:"DPAPI Activity"
	Auditpol /get /subcategory:"RPC Events"
	Auditpol /get /subcategory:"Process Creation"


	Write-Host 13.4 DS Access
	'======================='

	Auditpol /get /subcategory:"Detailed Directory Service Replication"
	Auditpol /get /subcategory:"Directory Service Access"
	Auditpol /get /subcategory:"Directory Service Changes"
	Auditpol /get /subcategory:"Directory Service Replication"



	Write-Host 13.5 Logon/Logoff
	'======================='

	Auditpol /get /subcategory:"Account Lockout"
	Auditpol /get /subcategory:"IPsec Extended Mode"
	Auditpol /get /subcategory:"IPsec Main Mode"
	Auditpol /get /subcategory:"IPsec Quick Mode"
	Auditpol /get /subcategory:"Logoff"
	Auditpol /get /subcategory:"Logon" 
	Auditpol /get /subcategory:"Network Policy Server"
	Auditpol /get /subcategory:"Other Logon/Logoff Events"
	Auditpol /get /subcategory:"Special Logon"



	Write-Host 13.6 Object Access
	'======================='

	Auditpol /get /subcategory:"Application Generated"
	Auditpol /get /subcategory:"Certification Services"
	Auditpol /get /subcategory:"Detailed File Share"

	Will generate a lot of events if Files and Reg keys are audited so only audit locations that are not noisy

	Auditpol /get /subcategory:"File Share"
	Auditpol /get /subcategory:"File System"
	Auditpol /get /subcategory:"Filtering Platform Connection" 
	Auditpol /get /subcategory:"Filtering Platform Packet Drop"
	Auditpol /get /subcategory:"Handle Manipulation"
	Auditpol /get /subcategory:"Kernel Object"
	Auditpol /get /subcategory:"Other Object Access Events"
	Auditpol /get /subcategory:"Registry"
	Auditpol /get /subcategory:"Removable Storage"
	Auditpol /get /subcategory:"SAM"


	Write-Host 13.7 Policy Change
	'======================='

	Auditpol /get /subcategory:"Audit Policy Change"
	Auditpol /get /subcategory:"Authentication Policy Change"
	Auditpol /get /subcategory:"Authorization Policy Change"

	Enable if you use Windows Firewall to monitor changes

	Auditpol /get /subcategory:"Filtering Platform Policy Change"
	Auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
	Auditpol /get /subcategory:"Other Policy Change Events"



	Write-Host 13.8 Privilege Use
	'======================='

	Auditpol /get /subcategory:"Other Privilege Use Events"
	Auditpol /get /subcategory:"Non Sensitive Privilege Use"
	Auditpol /get /subcategory:"Sensitive Privilege Use"



	Write-Host 13.9 SYSTEM AUDIT
	'======================='

	Auditpol /get /subcategory:"IPsec Driver"
	Auditpol /get /subcategory:"Other System Events"
	Auditpol /get /subcategory:"Security State Change"
	Auditpol /get /subcategory:"Security System Extension"
	Auditpol /get /subcategory:"System Integrity"

'=========================================================='
Write-Host 14. EVENT LOG INFORMATION
'=========================================================='
Get-WinEvent -ListLog * | where {$_.RecordCount -gt 0}

'=========================================================='
Write-Host 15. SYSTEM FOLDER PERMISSION
'=========================================================='
get-acl C:\Windows\System32 | fl

'===================================================================================='
Write-Host 16. DIRECTORIES THAT CONATAIN SENSITIVE WINDOWS SYSTEM FILES SHOULD BE SECURED
'===================================================================================='
Get-Acl "$env:SystemRoot" | Format-List | Out-Host
Get-Acl "$env:SystemRoot\System32" | Format-List | Out-Host
Get-Acl "$env:SystemRoot\System32\spool" | Format-List | Out-Host
Get-Acl "$env:SystemRoot\system32\drivers" | Format-List | Out-Host
Get-Acl "$env:SystemRoot\system32\config" | Format-List | Out-Host
Get-Acl "$env:SystemRoot\security" | Format-List | Out-Host

'======================================================================================'
Write-Host 17. KEY EXECUTABLE FILES SHOULD BE PROPERLY RESTRICTED FROM UNAUTHORISED USERS
'======================================================================================'
cacls "C:\Windows\system32\arp.exe"
cacls "C:\Windows\system32\at.exe"
cacls "C:\Windows\system32\attrib.exe"
cacls "C:\Windows\system32\cacls.exe"
cacls "C:\Windows\system32\cmd.exe"
cacls "C:\Windows\system32\eventcreate.exe"
cacls "C:\Windows\system32\finger.exe"
cacls "C:\Windows\system32\ftp.exe"
cacls "C:\Windows\system32\gpupdate.exe"
cacls "C:\Windows\system32\icacls.exe"
cacls "C:\Windows\system32\ipconfig.exe"
cacls "C:\Windows\system32\nbtstat.exe"
cacls "C:\Windows\system32\net.exe"
cacls "C:\Windows\system32\net1.exe"
cacls "C:\Windows\system32\netstat.exe"
cacls "C:\Windows\system32\nslookup.exe"
cacls "C:\Windows\system32\ping.exe"
cacls "C:\Windows\system32\reg.exe"
cacls "C:\Windows\system32\regedt32.exe"
cacls "C:\Windows\system32\regini.exe"
cacls "C:\Windows\system32\regsvr32.exe"
cacls "C:\Windows\system32\route.exe"
cacls "C:\Windows\system32\runonce.exe"
cacls "C:\Windows\system32\sc.exe"
cacls "C:\Windows\system32\secedit.exe"
cacls "C:\Windows\system32\subst.exe"
cacls "C:\Windows\system32\systeminfo.exe"
cacls "C:\Windows\system32\syskey.exe"
cacls "C:\Windows\system32\telnet.exe"
cacls "C:\Windows\system32\tracert.exe"
cacls "C:\Windows\system32\xcopy.exe"

'======================================================================================================='
Write-Host 18. LOCAL GROUPS SHOULD ONLY CONTAIN GLOBAL GROUPS THAT ARE AUTHORIZED FOR EACH PURPOSE
'======================================================================================================='
net localgroup

'=========================================================='
Write-Host 19. NETWORK CONFIGURATION
'=========================================================='

IPConfig /all

	'=========================================================='
		Write-Host 19.1 DETAILED NETWORK CONFIGURATION
	'=========================================================='
		Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS* 
		
'====================================='
Write-Host 20. REMOTE ASSISTANCE SETTINGS
'====================================='
qwinsta /server:$ServerName

'=========================================================='
Write-Host  21. DOMAIN PASSWORD POLICY
'=========================================================='	
net accounts /domain | Out-Host

function Get-PassPol
{
	$domain = [ADSI]"WinNT://$env:userdomain"
	$Name = @{Name='DomainName';Expression={$_.Name}}
	$MinPassLen = @{Name='Minimum Password Length (Chars)';Expression={$_.MinPasswordLength}}
	$MinPassAge = @{Name='Minimum Password Age (Days)';Expression={$_.MinPasswordAge.value/86400}}
	$MaxPassAge = @{Name='Maximum Password Age (Days)';Expression={$_.MaxPasswordAge.value/86400}}
	$PassHistory = @{Name='Enforce Password History (Passwords remembered)';Expression={$_.PasswordHistoryLength}}
	$AcctLockoutThreshold = @{Name='Account Lockout Threshold (Invalid logon attempts)';Expression={$_.MaxBadPasswordsAllowed}}
	$AcctLockoutDuration =  @{Name='Account Lockout Duration (Minutes)';Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	$ResetAcctLockoutCounter = @{Name='Reset Account Lockout Counter After (Minutes)';Expression={$_.LockoutObservationInterval.value/60}}
	$domain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
}
$PassPol = Get-PassPol
Write-Host 'Domain Password Policy: '
Write-Host $PassPol

'=========================================================='
Write-Host 22. COLLECT PHYSICAL MEMORY INFORMATION
'=========================================================='
Get-WmiObject -Class Win32_logicaldisk

'=========================================================='
Write-Host 23. SYSTEM FOLDER PERMISSIONS
'=========================================================='	

((Get-Item C:\*). GetAccessControl('Access')).Access

'=========================================================='
Write-Host  24. CHECK PROXY SETTING
'=========================================================='	

Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

'=========================================================='
Write-Host  25. PRINTER DETAILS
'=========================================================='	

Get-WMIObject Win32_Printer -ComputerName $env:COMPUTERNAME

'=========================================================='
Write-Host 26. TERMINAL SERVER SETTINGS 
'=========================================================='	

Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices | Get-Member -Type Methods

'=========================================================='
Write-Host 27. CRASH DETECTION LOG
'=========================================================='	

Get-Eventlog system -Newest 2000 | Where-Object {$_.entryType -Match "Error"}

'=========================================================='
Write-Host  28. ACCOUNT LOCKOUT POLICY
'=========================================================='	

net accounts
		
'=========================================================='      
 Write-Host  29. CHECK FOR THIRD PARTY FIREWALL PRODUCTS
'=========================================================='
 
netsh advfirewall monitor show firewall rule name=all dir=in
	
'=========================================================='
 Write-Host  30. CHECKS FOR ANTIVIRUS PRODUCTS
'=========================================================='
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

'=========================================================='
 Write-Host  31. FIREWALL PRESENT IN DOMAIN
'=========================================================='
$strFilter = "computer"
 
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
 
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.SearchScope = "Subtree" 
$objSearcher.PageSize = 1000 

$objSearcher.Filter = "(objectCategory=$strFilter)"

$colResults = $objSearcher.FindAll()

foreach ($i in $colResults) 
    {
        $objComputer = $i.GetDirectoryEntry()
		$objComputer.Name
        netsh -r $objComputer.Name advfirewall show allprofiles state 
    }


'=========================================================='
 Write-Host  32. FIREWALL STATUS - COMPLIANCE/NON-COMPLIANCE
'=========================================================='
$FirewallStatus = 0
$SysFirewallReg1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg1 -eq 1) {
$FirewallStatus = 1
}

$SysFirewallReg2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg2 -eq 1) {
$FirewallStatus = ($FirewallStatus + 1)
}

$SysFirewallReg3 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
If ($SysFirewallReg3 -eq 1) {
$FirewallStatus = ($FirewallStatus + 1)
}

If ($FirewallStatus -eq 3) {Write-Host "Compliant"}
ELSE {Write-Host "Non-Compliant"}

'=========================================================='
 Write-Host  End of the Script
'=========================================================='

Write-Host
Write-Host Script execution complete. Please Wait... -ForegroundColor Yellow -BackgroundColor Black
Write-Host
Start-Sleep -s 5
Write-Host Reverting the PowerShell script execution policy to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
    
    Start-Sleep -s 5
    Set-ExecutionPolicy $ExecutionPolicy -force

Write-Host
Write-Host The PowerShell Script Execution Policy setting has been reverted back to $ExecutionPolicy -ForegroundColor Yellow -BackgroundColor Black
Write-Host 
Write-Host All done. Have a good day.
Write-Host

'=========================================================='
 Write-Host CREATING ARCHIVE
'=========================================================='

'=========================================================='
 Write-Host  STOP RECORDING TRANSCRIPT
'=========================================================='
Stop-Transcript

'=========================================================='
 Write-Host  SUCCSSFULLY EXECUTED..!!!
'=========================================================='

