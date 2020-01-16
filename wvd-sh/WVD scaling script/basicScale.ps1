<#
Copyright 2019 Microsoft
Version 2.0 March 2019
.SYNOPSIS
This is a sample script for automatically scaling Tenant Environment WVD Host Servers in Microsoft Azure
.Description
This script will start/stop Tenant WVD host VMs based on the number of user sessions and peak/off-peak time period specified in the configuration file.
During the peak hours, the script will start necessary session hosts in the Hostpool to meet the demands of users.
During the off-peak hours, the script will shut down session hosts and only keep the minimum number of session hosts.
This script depends on two PowerShell modules: Azure RM and Windows Virtual Desktop modules. To install Azure RM module and WVD Module execute the following commands. Use "-AllowClobber" parameter if you have more than one version of PowerShell modules installed.
PS C:\>Install-Module Az  -AllowClobber
PS C:\>Install-Module Microsoft.RDInfra.RDPowershell  -AllowClobber
#>

# Setting ErrorActionPreference to stop script execution when error occurs
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Function for convert from UTC to Local time
function Convert-UTCtoLocalTime
{
	param(
		$TimeDifferenceInHours
	)

	$UniversalTime = (Get-Date).ToUniversalTime()
	$TimeDifferenceMinutes = 0
	if ($TimeDifferenceInHours -match ":") {
		$TimeDifferenceHours = $TimeDifferenceInHours.Split(":")[0]
		$TimeDifferenceMinutes = $TimeDifferenceInHours.Split(":")[1]
	}
	else {
		$TimeDifferenceHours = $TimeDifferenceInHours
	}
	#Azure is using UTC time, justify it to the local time
	$ConvertedTime = $UniversalTime.AddHours($TimeDifferenceHours).AddMinutes($TimeDifferenceMinutes)
	return $ConvertedTime
}

<#
.SYNOPSIS
Function for writing the log
#>
function Write-Log {
	param(
		[int]$Level
		,[string]$Message
		,[ValidateSet("Info","Warning","Error")] [string]$Severity = 'Info'
		,[string]$Logname = $WVDTenantlog
		,[string]$Color = "White"
	)
	$Time = Convert-UTCtoLocalTime -TimeDifferenceInHours $TimeDifference
	Add-Content $Logname -Value ("{0} - [{1}] {2}" -f $Time,$Severity,$Message)
	if ($interactive) {
		switch ($Severity) {
			'Error' { $Color = 'Red' }
			'Warning' { $Color = 'Yellow' }
		}
		if ($Level -le $VerboseLogging) {
			if ($Color -match "Red|Yellow") {
				Write-Output ("{0} - [{1}] {2}" -f $Time,$Severity,$Message) -ForegroundColor $Color -BackgroundColor Black
				if ($Severity -eq 'Error') {

					throw $Message
				}
			}
			else {
				Write-Output ("{0} - [{1}] {2}" -f $Time,$Severity,$Message) -ForegroundColor $Color
			}
		}
	}
	else {
		switch ($Severity) {
			'Info' { Write-Verbose -Message $Message }
			'Warning' { Write-Warning -Message $Message }
			'Error' {
				throw $Message
			}
		}
	}
}

<#
.SYNOPSIS
Function for writing the usage log
#>
function Write-UsageLog {
	param(
		[string]$HostpoolName,
		[int]$Corecount,
		[int]$VMCount,
		[bool]$DepthBool = $True,
		[string]$LogFileName = $WVDTenantUsagelog
	)
	$Time = Convert-UTCtoLocalTime -TimeDifferenceInHours $TimeDifference
	if ($DepthBool) {
		Add-Content $LogFileName -Value ("{0}, {1}, {2}" -f $Time,$HostpoolName,$VMCount)
	}

	else {

		Add-Content $LogFileName -Value ("{0}, {1}, {2}, {3}" -f $Time,$HostpoolName,$Corecount,$VMCount)
	}
}
<#
.SYNOPSIS
Function for creating a variable from JSON
#>
function Set-ScriptVariable ($Name,$Value) {
	Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}


#Function to Check if the session host is allowing new connections
function Check-ForAllowNewConnections
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$SessionHostName
	)

	# Check if the session host is allowing new connections
	$StateOftheSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
	if (!($StateOftheSessionHost.AllowNewSession)) {
		Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName -AllowNewSession $true
	}

}
# Start the Session Host 
function Start-SessionHost
{
	param(
		[string]$VMName
	)
	try {
		Get-AzVM | Where-Object { $_.Name -eq $VMName } | Start-AzVM -AsJob | Out-Null
	}
	catch {
		Write-Log 1 "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" "Error"
		exit
	}

}
# Stop the Session Host
function Stop-SessionHost
{
	param(
		[string]$VMName
	)
	try {
		Get-AzVM | Where-Object { $_.Name -eq $VMName } | Stop-AzVM -Force -AsJob | Out-Null
	}
	catch {
		Write-Log 1 "Failed to stop Azure VM: $($VMName) with error: $($_.exception.message)" "Error"
		exit
	}
}
# Check if the Session host is available
function Check-IfSessionHostIsAvailable
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$SessionHostName
	)
	$IsHostAvailable = $false
	while (!$IsHostAvailable) {
		$SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
		if ($SessionHostStatus.Status -eq "Available") {
			$IsHostAvailable = $true
		}
	}
	return $IsHostAvailable
}

# Function to update load balancer type in peak hours
function Updating-LoadBalancingTypeInPeakHours
{
	param(
		[string]$HostpoolLoadbalancerType,
		[string]$PeakloadbalancingType,
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$MaxSessionLimitValue
	)
	if ($HostpoolLoadbalancerType -ne $PeakLoadBalancingType) {
		Write-Log 3 "Changing hostpool load balancer type in peak hours current Date Time is: $CurrentDateTime"

		if ($hostpoolinfo.LoadBalancerType -ne "DepthFirst") {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -DepthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue

		} else {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -BreadthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue
		}
		$LoadBalancerType = $LoadBalanceType.LoadBalancerType
		Write-Log 3 "Hostpool load balancer type in peak hours is '$LoadBalancerType load balancing'"
	}
}
# Function to update load balancer type in off peak hours
function Updating-LoadBalancingTypeINOffPeakHours
{
	param(
		[string]$HostpoolLoadbalancerType,
		[string]$PeakloadbalancingType,
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$MaxSessionLimitValue
	)
	if ($HostpoolLoadbalancerType -eq $PeakLoadBalancingType) {
		Write-Log 3 "Changing hostpool load balancer type in off peak hours current Date Time is: $CurrentDateTime"


		if ($hostpoolinfo.LoadBalancerType -ne "DepthFirst") {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -DepthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue

		} else {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -BreadthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue
		}
		$LoadBalancerType = $LoadBalanceType.LoadBalancerType
		Write-Log 3 "Hostpool load balancer type in off peak hours is '$LoadBalancerType load balancing'"


	}
}



$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path

##### Json path #####
$JsonPath = "$CurrentPath\Config.Json"

##### Log path #####
$WVDTenantlog = "$CurrentPath\WVDTenantScale.log"

##### Usage log path #####
$WVDTenantUsagelog = "$CurrentPath\WVDTenantUsage.log"

###### Verify Json file ######
if (Test-Path $JsonPath) {
	Write-Verbose "Found $JsonPath"
	Write-Verbose "Validating file..."
	try {
		$Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
	}
	catch {
		#$Validate = $false
		Write-Error "$JsonPath is invalid. Check Json syntax - Unable to proceed"
		Write-Log 3 "$JsonPath is invalid. Check Json syntax - Unable to proceed" "Error"
		exit 1
	}
}
else {
	#$Validate = $false
	Write-Error "Missing $JsonPath - Unable to proceed"
	Write-Log 3 "Missing $JsonPath - Unable to proceed" "Error"
	exit 1
}
##### Load Json Configuration values as variables #########
Write-Verbose "Loading values from Config.Json"
$Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
$Variable.WVDScale.Azure | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.Deployment | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
##### Construct Begin time and End time for the Peak period from utc to local time #####
$TimeDifference = [string]$TimeDifferenceInHours
$CurrentDateTime = Convert-UTCtoLocalTime -TimeDifferenceInHours $TimeDifference

##### Load functions/module #####
. $CurrentPath\Functions-PSStoredCredentials.ps1
# Checking if the WVD Modules are existed
$WVDModules = Get-InstalledModule -Name "Microsoft.RDInfra.RDPowershell" -ErrorAction SilentlyContinue
if (!$WVDModules) {
	Write-Log 1 "WVD Modules doesn't exist. Ensure WVD Modules are installed if not execute this command 'Install-Module Microsoft.RDInfra.RDPowershell  -AllowClobber'"
	exit
}
Import-Module "Microsoft.RDInfra.RDPowershell"
##### Login with delegated access in WVD tenant #####
$Credentials = Get-StoredCredential -Username $Username

$isWVDServicePrincipal = ($isWVDServicePrincipal -eq "True")
##### Check if service principal or user account is being used for WVD and Azure #####
if (!$isWVDServicePrincipal) {
	##### If standard account is provided login in WVD with that account #####
	try {
		$WVDAuthentication = Add-RdsAccount -DeploymentUrl $RDBroker -Credential $Credentials
	}
	catch {
		Write-Log 1 "Failed to authenticate with WVD Tenant with a standard account: $($_.exception.message)" "Error"
		exit 1
	}
	$WVDObj = $WVDAuthentication | Out-String
	Write-Log 3 "Authenticating as standard account for WVD. Result: `n$WVDObj" "Info"


	##### If standard account is provided login in Azure with that account #####
	try {
		$AzAuthentication = Add-AzAccount -SubscriptionId $currentAzureSubscriptionId -Credential $Credentials
	}
	catch {
		Write-Log 1 "Failed to authenticate with Azure with a standard account: $($_.exception.message)" "Error"
		exit 1
	}
	$AzObj = $AzAuthentication | Out-String
	Write-Log 3 "Authenticating as standard account for Azure. Result: `n$AzObj" "Info"
}
else {
	##### When service principal account is provided login in WVD with that account #####

	try {
		$WVDauthentication = Add-RdsAccount -DeploymentUrl $RDBroker -TenantId $AADTenantId -Credential $Credentials -ServicePrincipal
	}
	catch {
		Write-Log 1 "Failed to authenticate with WVD Tenant with the service principal: $($_.exception.message)" "Error"
		exit 1
	}
	$WVDObj = $WVDAuthentication | Out-String
	Write-Log 3 "Authenticating as service principal account for WVD. Result: `n$WVDObj" "Info"

	##### When service principal account is provided login in WVD with that account #####
	try {
		$AzAuthentication = Add-AzAccount -Tenant $AADTenantId -Credential $Credentials -ServicePrincipal
	}
	catch {
		Write-Log 1 "Failed to authenticate with Azure with the service principal: $($_.exception.message)" "Error"
		exit 1
	}
	$AzObj = $AzAuthentication | Out-String
	Write-Log 3 "Authenticating as service principal account for WVD. Result: `n$AzObj" "Info"

}



##### Set context to the appropriate tenant group #####
#Set context to the appropriate tenant group
$CurrentTenantGroupName = (Get-RdsContext).TenantGroupName
if ($TenantGroupName -ne $CurrentTenantGroupName) {
	Write-Log 1 "Running switching to the $TenantGroupName context" "Info"
	Set-RdsContext -TenantGroupName $TenantGroupName
}

##### select the current Azure subscription specified in the config #####
Select-AzSubscription -SubscriptionId $CurrentAzureSubscriptionId

# Converting Datetime format
$BeginPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $BeginPeakTime)
$EndPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $EndPeakTime)

#Checking given host pool name exists in Tenant
$HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostpoolName
if ($HostpoolInfo -eq $null) {
	Write-Log 1 "Hostpoolname '$HostpoolName' does not exist in the tenant of '$TenantName'. Ensure that you have entered the correct values." "Info"
	exit
}


#Compare beginpeaktime and endpeaktime hours and setting up appropriate load balacing type based on PeakLoadBalancingType
# Setting up appropriate load balacing type based on PeakLoadBalancingType in Peak hours
$HostpoolLoadbalancerType = $HostpoolInfo.LoadBalancerType
[int]$MaxSessionLimitValue = $HostpoolInfo.MaxSessionLimit
if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
	Updating-LoadBalancingTypeInPeakHours -HostpoolLoadbalancerType $HostpoolLoadbalancerType -PeakLoadBalancingType $PeakLoadBalancingType -TenantName $TenantName -HostPoolName $HostpoolName -MaxSessionLimitValue $MaxSessionLimitValue
}
else {
	Updating-LoadBalancingTypeINOffPeakHours -HostpoolLoadbalancerType $HostpoolLoadbalancerType -PeakLoadBalancingType $PeakloadbalancingType -TenantName $TenantName -HostPoolName $HostpoolName -MaxSessionLimitValue $MaxSessionLimitValue
}

# Check if the hostpool have session hosts
$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -ErrorAction Stop | Sort-Object Status
if ($ListOfSessionHosts -eq $null) {
	Write-Log 1 "Session hosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?." "Info"
	exit
}


Write-Log 3 "Starting WVD Tenant Hosts Scale Optimization: Current Date Time is: $CurrentDateTime" "Info"
# After updating load balancer type
$HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostpoolName

if ($HostpoolInfo.LoadBalancerType -eq "DepthFirst") {

	Write-Log 1 "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)" "Info"

	#Gathering hostpool maximum session and calculating Scalefactor for each host.										  
	$HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
	$ScaleFactorEachHost = $HostpoolMaxSessionLimit * 0.80
	$SessionhostLimit = [math]::Floor($ScaleFactorEachHost)

	Write-Log 1 "Hostpool Maximum Session Limit: $($HostpoolMaxSessionLimit)"


	if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
		Write-Log 1 "It is in peak hours now" "Info"
		Write-Log 1 "Starting session hosts as needed based on current workloads." "Info"
		Write-Log 1 ("Processing hostPool {0}" -f $HostpoolName) "Info"

		# Check dynamically created offpeakusage-minimumnoofRDSh text file and will remove in peak hours.
		if (Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			Remove-Item -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
		}

		# Check the number of running session hosts
		$NumberOfRunningHost = 0

		#Initialize variable for to skip the session host which is in maintenance.
		$SkipSessionhosts = 0
		$SkipSessionhosts = @()
		$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -ErrorAction Stop | Sort-Object Sessions -Descending | Sort-Object Status
		foreach ($SessionHost in $ListOfSessionHosts) {
			$SessionHostName = $SessionHost.SessionHostName | Out-String
			$VMName = $SessionHostName.Split(".")[0]
			$VmInfo = Get-AzVM | Where-Object { $_.Name -eq $VMName }
			# Check the Session host is in maintenance
			if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
				Write-Log 1 "Session Host is in Maintenance: $SessionHostName, so script will skip this VM"
				$SkipSessionhosts += $SessionHost
				continue
			}

			#$AllSessionHosts = Compare-Object $ListOfSessionHosts $SkipSessionhosts | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }
			$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }

			Write-Log 1 "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)" "Info"
			$SessionCapacityofSessionHost = $SessionHost.Sessions

			if ($SessionHostLimit -lt $SessionCapacityofSessionHost -or $SessionHost.Status -eq "Available") {
				$NumberOfRunningHost = $NumberOfRunningHost + 1

			}
		}
		Write-Log 1 "Current number of running hosts: $NumberOfRunningHost" "Info"
		if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {
			Write-Log 1 "Current number of running session hosts is less than minimum requirements, start session host ..." "Info"

			foreach ($SessionHost in $AllSessionHosts) {

				if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {
					$SessionHostSessions = $SessionHost.Sessions
					if ($HostpoolMaxSessionLimit -ne $SessionHostSessions) {
						# Check the session host status and if the session host is healthy before starting the host
						if ($SessionHost.Status -eq "NoHeartbeat" -and $SessionHost.UpdateState -eq "Succeeded") {
							$SessionHostName = $SessionHost.SessionHostName | Out-String
							$VMName = $SessionHostName.Split(".")[0]
							# Check if the session host is allowing new connections
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost
							# Start the Az VM
							Write-Log 1 "Starting Azure VM: $VMName and waiting for it to complete ..."
							Start-SessionHost -VMName $VMName

							# Wait for the VM to Start
							$IsVMStarted = $false
							while (!$IsVMStarted) {
								$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
								if ($RoleInstance.PowerState -eq "VM running") {
									$IsVMStarted = $true
									Write-Log 1 "Azure VM has been Started: $($RoleInstance.Name) ..."
								}
							}
							# Wait for the VM to start
							$SessionHostIsAvailable = Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost
							if ($SessionHostIsAvailable) {
								Write-Log 1 "'$SessionHost' session host status is 'Available'"
							}
							else {
								Write-Log 1 "'$SessionHost' session host does not configured properly with deployagent or does not started properly"
							}

						}
					}
					$NumberOfRunningHost = $NumberOfRunningHost + 1
				}

			}
		}
		else {
			$TotalRunningHostSessionLimit = [math]::Floor($NumberOfRunningHost * $SessionhostLimit)
			$TotalUserSessions = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
			if ($TotalUserSessions -ge $TotalRunningHostSessionLimit) {
				$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Where-Object { $_.Status -eq "NoHeartBeat" }
				foreach ($SessionHost in $AllSessionHosts) {
					# Check the session host status and if the session host is healthy before starting the host
					if ($SessionHost.UpdateState -eq "Succeeded") {
						Write-Output "Existing Sessionhosts Sessions value reached near by hostpool maximumsession limit need to start the session host"
						$LogMessage = @{ hostpoolName_s = $HostpoolName; logmessage_s = "Existing Sessionhost Sessions value reached near by hostpool maximumsession limit need to start the session host" }
						Add-LogEntry -LogMessageObj $LogMessage -LogAnalyticsWorkspaceId $LogAnalyticsWorkspaceId -LogAnalyticsPrimaryKey $LogAnalyticsPrimaryKey -logType "WVDTenantScale_CL" -TimeDifferenceInHours $TimeDifference
						$SessionHostName = $SessionHost.SessionHostName | Out-String
						$VMName = $SessionHostName.Split(".")[0]

						# Validating session host is allowing new connections
						Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostPoolName -SessionHostName $SessionHost.SessionHostName

						# Start the Az VM
						Start-SessionHost -VMName $VMName

						# Wait for the sessionhost is available
						Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
						# Increment the number of running session host
						$NumberOfRunningHost = $NumberOfRunningHost + 1
						break
					}
				}

			}

		}

		Write-Log 1 "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost" "Info"
		$DepthBool = $true
		Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $DepthBool
	}
	else {
		Write-Log 1 "It is Off-peak hours" "Info"
		Write-Log 1 "Starting to scale down RD session hosts..." "Info"
		Write-Log 1 ("Processing hostPool {0}" -f $HostpoolName) "Info"
		# Get all session hosts in the host pool


		# Check the number of running session hosts
		$NumberOfRunningHost = 0
		#Initialize variable for to skip the session host which is in maintenance.
		$SkipSessionhosts = 0
		$SkipSessionhosts = @()

		$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions
		foreach ($SessionHost in $ListOfSessionHosts) {
			$SessionHostName = $SessionHost.SessionHostName
			$VMName = $SessionHostName.Split(".")[0]
			$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
			# Check the session host is in maintenance
			if ($RoleInstance.Tags.Keys -contains $MaintenanceTagName) {
				Write-Log 1 "Session host is in maintenance: $VMName, so script will skip this VM"
				$SkipSessionhosts += $SessionHost
				continue
			}
			# Maintenance VMs skipped and stored into a variable
			$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }
			if ($SessionHost.Status -eq "Available") {
				Write-Log 1 "CheckSing session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)" "Info"
				$NumberOfRunningHost = $NumberOfRunningHost + 1
			}
		}
		# Defined minimum no of rdsh value from JSON file
		[int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH

		# Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
		if (Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			[int]$MinimumNumberOfRDSH = Get-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
		}

		if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
			foreach ($SessionHost in $AllSessionHosts) {
				if ($SessionHost.Status -ne "NoHeartbeat") {
					if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
						$SessionHostName = $SessionHost.SessionHostName
						$VMName = $SessionHostName.Split(".")[0]
						if ($SessionHost.Sessions -eq 0) {
							# Shutdown the Azure VM, which session host have 0 sessions
							Write-Log 1 "Stopping Azure VM: $VMName and waiting for it to complete ..."
							Stop-SessionHost -VMName $VMName
						}
						else {
							# Ensure the running Azure VM is set as drain mode
							try {
								$KeepDrianMode = Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName -AllowNewSession $false -ErrorAction Stop
							}
							catch {
								Write-Log 1 "Unable to set it to allow connections on session host: $SessionHostName with error: $($_.exception.message)"
								exit
							}
							# Notify user to log off session
							# Get the user sessions in the hostpool
							try {
								$HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName | Where-Object { $_.SessionHostName -eq $SessionHostName }
							}
							catch {
								Write-Log 1 "Failed to retrieve user sessions in hostpool: $($Name) with error: $($_.exception.message)" "Error"
								exit
							}
							$HostUserSessionCount = ($HostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostName -eq $SessionHostName }).Count
							Write-Log 1 "Counting the current sessions on the host $SessionHostName :$HostUserSessionCount"
							$ExistingSession = 0
							foreach ($session in $HostPoolUserSessions) {
								if ($session.SessionHostName -eq $SessionHostName -and $session.SessionState -eq "Active") {
									if ($LimitSecondsToForceLogOffUser -ne 0) {
										# Send notification
										try {
											Send-RdsUserSessionMessage -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHostName -SessionId $session.SessionId -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt -ErrorAction Stop
										}
										catch {
											Write-Log 1 "Failed to send message to user with error: $($_.exception.message)" "Error"
											exit
										}
										Write-Log 1 "Script was sent a log off message to user: $($Session.UserPrincipalName | Out-String)"
									}
								}
								$ExistingSession = $ExistingSession + 1
							}
							# Wait for n seconds to log off user
							Start-Sleep -Seconds $LimitSecondsToForceLogOffUser

							if ($LimitSecondsToForceLogOffUser -ne 0) {
								# Force users to log off
								Write-Log 1 "Force users to log off ..."
								foreach ($Session in $HostPoolUserSessions) {
									if ($Session.SessionHostName -eq $SessionHostName) {
										#Log off user
										try {
											Invoke-RdsUserSessionLogoff -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $Session.SessionHostName -SessionId $Session.SessionId -NoUserPrompt -ErrorAction Stop
											$ExistingSession = $ExistingSession - 1
										}
										catch {
											Write-Log 1 " to log off user with error: $($_.exception.message)" "Error"
											exit
										}
										Write-Log 1 "Forcibly logged off the user: $($Session.UserPrincipalName | Out-String)"
									}
								}
							}


							# Check the session count before shutting down the VM
							if ($ExistingSession -eq 0) {
								# Shutdown the Azure VM
								Write-Log 1 "Stopping Azure VM: $VMName and waiting for it to complete ..."
								Stop-SessionHost -VMName $VMName
							}
						}

						#wait for the VM to stop
						$IsVMStopped = $false
						while (!$IsVMStopped) {
							$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
							if ($RoleInstance.PowerState -eq "VM deallocated") {
								$IsVMStopped = $true
								Write-Log 1 "Azure VM has been stopped: $($RoleInstance.Name) ..."
							}
						}
						# Check if the session host status is NoHeartbeat                            
						$IsSessionHostNoHeartbeat = $false
						while (!$IsSessionHostNoHeartbeat) {
							$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
							if ($SessionHostInfo.UpdateState -eq "Succeeded" -and $SessionHostInfo.Status -eq "NoHeartbeat") {
								$IsSessionHostNoHeartbeat = $true

								# Ensure the Azure VMs that are off have allow new connections mode set to True
								if ($SessionHostInfo.AllowNewSession -eq $false) {
									Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHostName
								}


							}
						}
						[int]$NumberOfRunningHost = [int]$NumberOfRunningHost - 1
					}
				}
			}
		}

		# Check whether minimumNoofRDSH Value stored dynamically
		if (Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			[int]$MinimumNumberOfRDSH = Get-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
			$NoConnectionsofhost = 0
			if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {
				foreach ($SessionHost in $AllSessionHosts) {
					if ($SessionHost.Status -eq "Available" -and $SessionHost.Sessions -eq 0) {
						$NoConnectionsofhost = $NoConnectionsofhost + 1

					}
				}
				if ($NoConnectionsofhost -gt $DefinedMinimumNumberOfRDSH) {
					[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH - $NoConnectionsofhost
					Clear-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
					Set-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
				}
			}
		}


		$HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
		$HostpoolSessionCount = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
		if ($HostpoolSessionCount -ne 0) {

			# Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours and calculate TotalAllowSessions Scale Factor
			$TotalAllowSessionsInOffPeak = [int]$MinimumNumberOfRDSH * $HostpoolMaxSessionLimit
			$SessionsScaleFactor = $TotalAllowSessionsInOffPeak * 0.90
			$ScaleFactor = [math]::Floor($SessionsScaleFactor)
			if ($HostpoolSessionCount -ge $ScaleFactor) {
				$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Where-Object { $_.Status -eq "NoHeartbeat" }
				#$AllSessionHosts = Compare-Object $ListOfSessionHosts $SkipSessionhosts | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }
				$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }
				foreach ($SessionHost in $AllSessionHosts) {
					# Check the session host status and if the session host is healthy before starting the host
					if ($SessionHost.UpdateState -eq "Succeeded") {
						Write-Log 1 "Existing sessionhost sessions value reached near by hostpool maximumsession limit need to start the session host" "Info"
						$SessionHostName = $SessionHost.SessionHostName | Out-String
						$VMName = $SessionHostName.Split(".")[0]
						# Validating session host is allowing new connections
						Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost.SessionHostName
						# Start the Az VM
						Write-Log 1 "Starting Azure VM: $VMName and waiting for it to complete ..." "Info"
						Start-SessionHost -VMName $VMName
						#Wait for the VM to start
						$IsVMStarted = $false
						while (!$IsVMStarted) {
							$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
							if ($RoleInstance.PowerState -eq "VM running") {
								$IsVMStarted = $true
								Write-Log 1 "Azure VM has been started: $($RoleInstance.Name) ..." "Info"
							}
						}

						# Wait for the sessionhost is available
						$SessionHostIsAvailable = Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
						if ($SessionHostIsAvailable) {
							Write-Log 1 "'$($SessionHost.SessionHostName | Out-String)' session host status is 'Available'" "Info"
						}
						else {
							Write-Log 1 "'$($SessionHost.SessionHostName | Out-String)' session host does not configured properly with deployagent or does not started properly" "Error"
						}

						# Increment the number of running session host
						[int]$NumberOfRunningHost = [int]$NumberOfRunningHost + 1
						# Increment the number of minimumnumberofrdsh
						[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH + 1

						if (!(Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt)) {
							New-Item -ItemType File -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
							Add-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
						}
						else {
							Clear-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
							Set-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
						}
						break
					}
					#Break # break out of the inner foreach loop once a match is found and checked
				}
			}

		}
		Write-Log 1 "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost" "Info"
		$DepthBool = $true
		Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $DepthBool
	}
	Write-Log 3 "End WVD Tenant Scale Optimization." "Info"

}
else {
	Write-Log 3 "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)" "Info"
	# check if it is during the peak or off-peak time
	if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
		Write-Log 1 "It is in peak hours now" "Info"
		Write-Log 3 "Starting session hosts as needed based on current workloads." "Info"
		Write-Log 1 ("Processing hostPool {0}" -f $HostpoolName) "Info"
		# Check and Remove the MinimumnoofRDSH value dynamically stored file												   
		if (Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			Remove-Item -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
		}

		# Check the number of running session hosts
		$NumberOfRunningHost = 0

		# Total of running cores
		$TotalRunningCores = 0

		# Total capacity of sessions of running VMs
		$AvailableSessionCapacity = 0

		#Initialize variable for to skip the session host which is in maintenance.
		$SkipSessionhosts = 0
		$SkipSessionhosts = @()
		$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -ErrorAction Stop | Sort-Object Sessions -Descending | Sort-Object Status


		foreach ($SessionHost in $ListOfSessionHosts) {

			$SessionHostName = $SessionHost.SessionHostName | Out-String
			$VMName = $SessionHostName.Split(".")[0]
			$VmInfo = Get-AzVM | Where-Object { $_.Name -eq $VMName }
			# Check the Session host is in maintenance
			if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
				Write-Log 1 "Session Host is in Maintenance: $SessionHostName, so script will skip this VM"
				$SkipSessionhosts += $SessionHost
				continue
			}

			#$AllSessionHosts = Compare-Object $ListOfSessionHosts $SkipSessionhosts | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }
			$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }


			Write-Log 1 "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)" "Info"
			$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
			if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
				# Check if the azure vm is running       
				if ($RoleInstance.PowerState -eq "VM running") {
					$NumberOfRunningHost = $NumberOfRunningHost + 1
					# Calculate available capacity of sessions						
					$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
					$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
					$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
				}

			}

		}
		Write-Log 1 "Current number of running hosts:$NumberOfRunningHost" "Info"

		if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {

			Write-Log 1 "Current number of running session hosts is less than minimum requirements, start session host ..." "Info"

			# Start VM to meet the minimum requirement            
			foreach ($SessionHost in $AllSessionHosts.SessionHostName) {

				# Check whether the number of running VMs meets the minimum or not
				if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {

					$VMName = $SessionHost.Split(".")[0]

					$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

					if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {

						# Check if the Azure VM is running and if the session host is healthy
						$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
						if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
							# Check if the session host is allowing new connections
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost
							# Start the Az VM
							Write-Log 1 "Starting Azure VM: $VMName and waiting for it to complete ..."
							Start-SessionHost -VMName $VMName

							# Wait for the VM to Start
							$IsVMStarted = $false
							while (!$IsVMStarted) {
								$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
								if ($RoleInstance.PowerState -eq "VM running") {
									$IsVMStarted = $true
									Write-Log 1 "Azure VM has been Started: $($RoleInstance.Name) ..."
								}
							}
							# Wait for the VM to start
							$SessionHostIsAvailable = Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost
							if ($SessionHostIsAvailable) {
								Write-Log 1 "'$SessionHost' session host status is 'Available'"
							}
							else {
								Write-Log 1 "'$SessionHost' session host does not configured properly with deployagent or does not started properly"
							}
							# Calculate available capacity of sessions
							$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
							$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
							[int]$NumberOfRunningHost = [int]$NumberOfRunningHost + 1
							[int]$TotalRunningCores = [int]$TotalRunningCores + $RoleSize.NumberOfCores
							if ($NumberOfRunningHost -ge $MinimumNumberOfRDSH) {
								break;
							}

						}
					}
				}
			}
		}

		else {
			#check if the available capacity meets the number of sessions or not
			$HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
			Write-Log 1 "Current total number of user sessions: $(($HostPoolUserSessions).Count)"
			Write-Log 1 "Current available session capacity is: $AvailableSessionCapacity"
			if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
				Write-Log 1 "Current available session capacity is less than demanded user sessions, starting session host"
				# Running out of capacity, we need to start more VMs if there are any 
				foreach ($SessionHost in $AllSessionHosts.SessionHostName) {
					if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
						$VMName = $SessionHost.Split(".")[0]
						$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

						if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {
							# Check if the Azure VM is running and if the session host is healthy
							$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
							if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
								# Validating session host is allowing new connections
								Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost
								# Start the Az VM
								Write-Log 1 "Starting Azure VM: $VMName and waiting for it to complete ..."
								Start-SessionHost -VMName $VMName
								# Wait for the VM to Start
								$IsVMStarted = $false
								while (!$IsVMStarted) {
									$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
									if ($RoleInstance.PowerState -eq "VM running") {
										$IsVMStarted = $true
										Write-Log 1 "Azure VM has been Started: $($RoleInstance.Name) ..."
									}
								}
								$SessionHostIsAvailable = Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost
								if ($SessionHostIsAvailable) {
									Write-Log 1 "'$SessionHost' session host status is 'Available'"
								}
								else {
									Write-Log 1 "'$SessionHost' session host does not configured properly with deployagent or does not started properly"
								}
								# Calculate available capacity of sessions
								$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
								$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
								[int]$NumberOfRunningHost = [int]$NumberOfRunningHost + 1
								[int]$TotalRunningCores = [int]$TotalRunningCores + $RoleSize.NumberOfCores
								Write-Log 1 "New available session capacity is: $AvailableSessionCapacity"
								if ($AvailableSessionCapacity -gt $HostPoolUserSessions.Count) {
									break
								}
							}
							#Break # break out of the inner foreach loop once a match is found and checked
						}
					}
				}
			}
		}
		Write-Log 1 "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost" "Info"
		# Write to the usage log
		$DepthBool = $false
		Write-UsageLog -HostPoolName $HostpoolName -Corecount $TotalRunningCores -VMCount $NumberOfRunningHost -DepthBool $DepthBool
	}
	else {

		Write-Log 1 "It is Off-peak hours" "Info"
		Write-Log 3 "Starting to scale down RD session hosts..." "Info"
		Write-Log 3 "Processing hostPool $($HostpoolName)"

		# Check the number of running session hosts
		$NumberOfRunningHost = 0

		# Total number of running cores
		$TotalRunningCores = 0

		#Initialize variable for to skip the session host which is in maintenance.
		$SkipSessionhosts = 0
		$SkipSessionhosts = @()
		$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions
		foreach ($SessionHost in $ListOfSessionHosts) {
			$SessionHostName = $SessionHost.SessionHostName
			$VMName = $SessionHostName.Split(".")[0]
			$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
			# Check the session host is in maintenance
			if ($RoleInstance.Tags.Keys -contains $MaintenanceTagName) {
				Write-Log 1 "Session host is in maintenance: $VMName, so script will skip this VM"
				$SkipSessionhosts += $SessionHost
				continue
			}
			# Maintenance VMs skipped and stored into a variable
			$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }
			if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
				# Check if the Azure VM is running
				if ($RoleInstance.PowerState -eq "VM running") {
					Write-Log 1 "Checking session host: $($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
					[int]$NumberOfRunningHost = [int]$NumberOfRunningHost + 1
					# Calculate available capacity of sessions  
					$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
					[int]$TotalRunningCores = [int]$TotalRunningCores + $RoleSize.NumberOfCores
				}
			}
		}

		# Defined minimum no of rdsh value from JSON file
		[int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH

		# Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
		if (Test-Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			[int]$MinimumNumberOfRDSH = Get-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
		}

		if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {


			# Shutdown VM to meet the minimum requirement
			foreach ($SessionHost in $AllSessionHosts) {
				#Check the status of the session host
				if ($SessionHost.Status -ne "NoHeartbeat") {
					if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
						$SessionHostName = $SessionHost.SessionHostName
						$VMName = $SessionHostName.Split(".")[0]
						if ($SessionHost.Sessions -eq 0) {
							# Shutdown the Azure VM, which session host have 0 sessions
							Write-Log 1 "Stopping Azure VM: $VMName and waiting for it to complete ..."
							Stop-SessionHost -VMName $VMName
						}
						else {
							# Ensure the running Azure VM is set as drain mode
							try {
								$KeepDrianMode = Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName -AllowNewSession $false -ErrorAction Stop
							}
							catch {
								Write-Log 1 "Unable to set it to allow connections on session host: $SessionHostName with error: $($_.exception.message)"
								exit
							}
							# Notify user to log off session
							# Get the user sessions in the hostpool
							try {
								$HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName | Where-Object { $_.SessionHostName -eq $SessionHostName }
							}
							catch {
								Write-Log 1 "Failed to retrieve user sessions in hostpool: $($Name) with error: $($_.exception.message)" "Error"
								exit
							}
							$HostUserSessionCount = ($HostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostName -eq $SessionHostName }).Count
							Write-Log 1 "Counting the current sessions on the host $SessionHostName :$HostUserSessionCount"
							$ExistingSession = 0
							foreach ($session in $HostPoolUserSessions) {
								if ($session.SessionHostName -eq $SessionHostName -and $session.SessionState -eq "Active") {
									if ($LimitSecondsToForceLogOffUser -ne 0) {
										# Send notification
										try {
											Send-RdsUserSessionMessage -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHostName -SessionId $session.SessionId -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt -ErrorAction Stop
										}
										catch {
											Write-Log 1 "Failed to send message to user with error: $($_.exception.message)" "Error"
											exit
										}
										Write-Log 1 "Script was sent a log off message to user: $($Session.UserPrincipalName | Out-String)"
									}
								}
								$ExistingSession = $ExistingSession + 1
							}
							# Wait for n seconds to log off user
							Start-Sleep -Seconds $LimitSecondsToForceLogOffUser

							if ($LimitSecondsToForceLogOffUser -ne 0) {
								# Force users to log off
								Write-Log 1 "Force users to log off ..."
								foreach ($Session in $HostPoolUserSessions) {
									if ($Session.SessionHostName -eq $SessionHostName) {
										#Log off user
										try {
											Invoke-RdsUserSessionLogoff -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $Session.SessionHostName -SessionId $Session.SessionId -NoUserPrompt -ErrorAction Stop
											$ExistingSession = $ExistingSession - 1
										}
										catch {
											Write-Log 1 " to log off user with error: $($_.exception.message)" "Error"
											exit
										}
										Write-Log 1 "Forcibly logged off the user: $($Session.UserPrincipalName | Out-String)"
									}
								}
							}


							# Check the session count before shutting down the VM
							if ($ExistingSession -eq 0) {
								# Shutdown the Azure VM
								Write-Log 1 "Stopping Azure VM: $VMName and waiting for it to complete ..."
								Stop-SessionHost -VMName $VMName
							}
						}

						#wait for the VM to stop
						$IsVMStopped = $false
						while (!$IsVMStopped) {
							$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
							if ($RoleInstance.PowerState -eq "VM deallocated") {
								$IsVMStopped = $true
								Write-Log 1 "Azure VM has been stopped: $($RoleInstance.Name) ..."
							}
						}
						# Check if the session host status is NoHeartbeat                            
						$IsSessionHostNoHeartbeat = $false
						while (!$IsSessionHostNoHeartbeat) {
							$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
							if ($SessionHostInfo.UpdateState -eq "Succeeded" -and $SessionHostInfo.Status -eq "NoHeartbeat") {
								$IsSessionHostNoHeartbeat = $true
								# Ensure the Azure VMs that are off have allow new connections mode set to True
								if ($SessionHostInfo.AllowNewSession -eq $false) {
									Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHostName
								}
							}
						}

						$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
						#decrement number of running session host
						[int]$NumberOfRunningHost = [int]$NumberOfRunningHost - 1
						[int]$TotalRunningCores = [int]$TotalRunningCores - $RoleSize.NumberOfCores
					}
				}
			}

		}

		# Check whether minimumNoofRDSH Value stored dynamically and calculate minimumNoOfRDSh value
		if (Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt) {
			[int]$MinimumNumberOfRDSH = Get-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
			$NoConnectionsofhost = 0
			if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {
				$MinimumNumberOfRDSH = $NumberOfRunningHost
				$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object sessions | Sort-Object status
				foreach ($SessionHost in $AllSessionHosts) {
					if ($SessionHost.Status -eq "Available" -and $SessionHost.Sessions -eq 0) {
						$NoConnectionsofhost = $NoConnectionsofhost + 1

					}
				}
				if ($NoConnectionsofhost -gt $DefinedMinimumNumberOfRDSH) {
					[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH - $NoConnectionsofhost
					Clear-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
					Set-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
				}
			}
		}
		# Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours
		$HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
		$HostpoolSessionCount = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
		if ($HostpoolSessionCount -ne 0) {
			# Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours and calculate TotalAllowSessions Scale Factor
			$TotalAllowSessionsInOffPeak = [int]$MinimumNumberOfRDSH * $HostpoolMaxSessionLimit
			$SessionsScaleFactor = $TotalAllowSessionsInOffPeak * 0.90
			$ScaleFactor = [math]::Floor($SessionsScaleFactor)


			if ($HostpoolSessionCount -ge $ScaleFactor) {
				$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Where-Object { $_.Status -eq "NoHeartbeat" }
				#$AllSessionHosts = Compare-Object $ListOfSessionHosts $SkipSessionhosts | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }
				$AllSessionHosts = $ListOfSessionHosts | Where-Object { $SkipSessionhosts -notcontains $_ }
				foreach ($SessionHost in $AllSessionHosts) {
					# Check the session host status and if the session host is healthy before starting the host
					if ($SessionHost.UpdateState -eq "Succeeded") {
						Write-Log 1 "Existing sessionhost sessions value reached near by hostpool maximumsession limit need to start the session host" "Info"
						$SessionHostName = $SessionHost.SessionHostName | Out-String
						$VMName = $SessionHostName.Split(".")[0]
						# Validating session host is allowing new connections
						Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost.SessionHostName
						# Start the Az VM
						Write-Log 1 "Starting Azure VM: $VMName and waiting for it to complete ..." "Info"
						Start-SessionHost -VMName $VMName
						#Wait for the VM to start
						$IsVMStarted = $false
						while (!$IsVMStarted) {
							$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
							if ($RoleInstance.PowerState -eq "VM running") {
								$IsVMStarted = $true
								Write-Log 1 "Azure VM has been started: $($RoleInstance.Name) ..." "Info"
							}
						}

						# Wait for the sessionhost is available
						$SessionHostIsAvailable = Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
						if ($SessionHostIsAvailable) {
							Write-Log 1 "'$($SessionHost.SessionHostName | Out-String)' session host status is 'Available'" "Info"
						}
						else {
							Write-Log 1 "'$($SessionHost.SessionHostName | Out-String)' session host does not configured properly with deployagent or does not started properly" "Error"
						}

						# Calculate available capacity of sessions
						$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
						$AvailableSessionCapacity = $TotalAllowSessions + $HostpoolInfo.MaxSessionLimit
						[int]$TotalRunningCores = [int]$TotalRunningCores + $RoleSize.NumberOfCores
						Write-Log 1 "New available session capacity is: $AvailableSessionCapacity" "Info"

						# Increment the number of running session host
						[int]$NumberOfRunningHost = [int]$NumberOfRunningHost + 1
						# Increment the number of minimumnumberofrdsh
						[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH + 1

						if (!(Test-Path -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt)) {
							New-Item -ItemType File -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
							Add-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
						}
						else {
							Clear-Content -Path $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt
							Set-Content $CurrentPath\OffPeakUsage-MinimumNoOfRDSH.txt $MinimumNumberOfRDSH
						}
						break
					}
					#Break # break out of the inner foreach loop once a match is found and checked
				}
			}
		}

		Write-Log 1 "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost" "Info"
		#write to the usage log
		$DepthBool = $false
		Write-UsageLog -HostPoolName $HostpoolName -Corecount $TotalRunningCores -VMCount $NumberOfRunningHost -DepthBool $DepthBool
	}
	Write-Log 3 "End WVD Tenant Scale Optimization." "Info"

} #Scale hostPool

