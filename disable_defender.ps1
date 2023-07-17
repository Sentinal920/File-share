############################
# Disable Windows Defender #
############################
# 1) Signature RollBack
# 2) Set Registry Key
# 3) Modify Group Policy ## TODO
# 4) Disable via DISM
############################

Write-Output "5) Disable Windows Defender "
# 1) Windows Defender Signature RollBack ('foreach' in the event of multiple versions)
if (Test-Path -Path 'C:\ProgramData\Microsoft\Windows Defender\Platform\')
{
	$dir='C:\ProgramData\Microsoft\Windows Defender\Platform\'
	$data=(Get-ChildItem $dir | sort LastWriteTime).name | Out-Null 
	foreach($d in $data)
	{
	   if (Test-Path $dir$d'\MpCmdRun.exe')
		{
		  & $dir$d'\MpCmdRun.exe -RemoveDefinitions -All'
		  & $dir$d'\MpCmdRun.exe -RemoveDefinitions -Engine'
		  & $dir$d'\MpCmdRun.exe -RemoveDefinitions -DynamicSignatures'
		}		
	}
}
if (Test-Path -Path 'C:\Program Files\Windows Defender\')
{
	$dir='C:\Program Files\Windows Defender\'
	if (Test-Path $dir'\MpCmdRun.exe')
		{
		  & $dir'\MpCmdRun.exe -RemoveDefinitions -All'
		  & $dir'\MpCmdRun.exe -RemoveDefinitions -Engine'
		  & $dir'\MpCmdRun.exe -RemoveDefinitions -DynamicSignatures'
		}		
}
# 2) Set registry to turn off Windows Defender Signature Updates
if (Test-Path -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender'  -ErrorAction Ignore) 
 {
  if (Test-Path -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'  -ErrorAction Ignore)
	{
	 Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name AVSignatureDue -value 0 | Out-Null
	 Write-Output "   *Registry key Set"
	}
  else
	{
	 New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Signature Updates' | Out-Null
     New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name AVSignatureDue -Value 0 | Out-Null
     Write-Output "   *Registry key Set"
    }
 } 
else 
 {
  New-Item -Path 'HKLM:\Software\Policies\Microsoft\' -Name 'Windows Defender' | Out-Null
  New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Signature Updates' | Out-Null
  New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name AVSignatureDue -Value 0 | Out-Null
  Write-Output "   *Registry key Set"
 }
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null

# 4) Disable via DISM 
try {dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet | Out-Null}
catch {"   *Windows-Defender Feature not found"}
try {dism /online /Disable-Feature /FeatureName:Windows-Defender-Features /Remove /NoRestart /quiet | Out-Null}
catch {"   *Windows-Defender-Features Feature not found"}
# Uninstall just in case 
try {Uninstall-WindowsFeature -Name Windows-Defender | Out-Null}
catch {"   *Windows-Defender Feature not found"}

## For Windows 10 PRO
Set-MpPreference -DisableRealtimeMonitoring $true
New-Item -Path 'HKLM:\Software\Policies\Microsoft\' -Name 'Windows Defender' | out-null
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Signature Updates' | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name ForceUpdateFromMU -Value 0 | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates' -Name AVSignatureDue -Value 0 | out-null
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Real-Time Protection' | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 1 | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableOnAccessProtection -Value 1 | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableBehaviorMonitoring -Value 1 | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableScanOnRealtimeEnable -Value 1 | out-null
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -Name 'Spynet' | out-null
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet' -Name DisableBlockAtFirstSeen -Value 1 | out-null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | out-null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWORD -Force | out-null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableRoutinelyTakingAction -Value 1 -PropertyType DWORD -Force | out-null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableSpecialRunningModes -Value 1 -PropertyType DWORD -Force | out-null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name ServiceKeepAlive -Value 0 -PropertyType DWORD -Force | out-null
