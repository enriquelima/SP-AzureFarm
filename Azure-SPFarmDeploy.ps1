Param
(
    [string]$SubscriptionName,
    [string]$StorageAccountName,
    [string]$Location,
    [string]$VNETName,
    [string]$AffinityGroup,
    [string]$SubnetSPFarmTier,
    [string]$ServiceNameDCTier,
    [string]$ServiceNameSQLTier,
    [string]$ServiceNameSPTier,
    [string]$domain,
    [string]$domainjoin,
    [string]$adminname,
    [string]$adminpassword
)

##$adminname = "labadmin"
##$adminpassword = "pass@word1"
##$domainjoin = "contoso.com"
##$domain = "contoso"
##$VNETName = "splabeelz01" ##Needs to be created upfront. Change the name as required
##$AffinityGroup = "agSPFARM01" ##Created during execution, replace xx with characters or numbers unique to you
##$ServiceNameDCTier = "svceelzdc01" ##Created during execution, make sure it is a unique value
##$SubnetSPFarmTier = "spsubnet" ##Needs to be created upfront. Change the name as required
##$ServiceNameSQLTier ="svceelzsql01" ##Created during execution, make sure it is a unique value
##$ServiceNameSPTier = "svceelzsp01"
##$Location = “Central US” ##Adjust as required, must be in the same Location as your VNET 
##$StorageAccountName = "storspfarmeel01" ##Created during execution, must be unique.
##$SubscriptionName = "Azure Pass" ## If not sure, use Get-AzureSubscription and record the value


#Add Function
#Import-Module ".\InstallWinRMCert.ps1"
function getLatestVMImage($imageFamily)
{
    $images = Get-AzureVMImage |
    where { $_.ImageFamily -eq $imageFamily } |
    Sort-Object -Descending -Property PublishedDate
    $latestImage = $images[0]
    return $latestimage
}


function InstallWinRMCert($serviceName, $vmname)
{
    $winRMCert = (Get-AzureVM -ServiceName $serviceName -Name $vmname | select -ExpandProperty vm).DefaultWinRMCertificateThumbprint
 
    $AzureX509cert = Get-AzureCertificate -ServiceName $serviceName -Thumbprint $winRMCert -ThumbprintAlgorithm sha1
 
    $certTempFile = [IO.Path]::GetTempFileName()
    Write-Host $certTempFile
    $AzureX509cert.Data | Out-File $certTempFile
 
    # Target The Cert That Needs To Be Imported
    $CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certTempFile
 
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
    $store.Certificates.Count
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($CertToImport)
    $store.Close()
 
    Remove-Item $certTempFile
}

#Creates AffinityGroup
New-AzureAffinityGroup –Name $AffinityGroup -Location $Location

#Creates Storage Subscription Account
New-AzureStorageAccount –StorageAccountName $StorageAccountName -AffinityGroup $AffinityGroup
Set-AzureSubscription -SubscriptionName $SubscriptionName -CurrentStorageAccountName $StorageAccountName

#Create a Storage Container to hold the VHD Files
New-AzureStorageContainer -Name "vhds"

$adimage = getLatestVMImage("Windows Server 2012 Datacenter")
$sqlImage = getLatestVMImage("SQL Server 2012 SP2 Enterprise on Windows Server 2012")
$spImage = getLatestVMImage("SharePoint Server 2013 Trial")

$credential = Get-Credential -UserName $adminname -Message "Enter VM Admin Password"


#Create AD VM
New-AzureVMConfig -Name "SPDC01" -InstanceSize Small -ImageName $adImage.ImageName |
    Add-AzureProvisioningConfig -Windows -AdminUsername $adminname -Password $adminpassword  |
    Set-AzureSubnet -SubnetNames $SubnetSPFarmTier |
    Add-AzureDataDisk -CreateNew -DiskSizeInGB 100 -LUN 0 -DiskLabel "ADData" |
    New-AzureVM -ServiceName $ServiceNameDCTier -AffinityGroup $AffinityGroup -VNetName $VNETName -WaitForBoot

#Set up RemotePowerShell
# Get the RemotePS/WinRM Uri to connect to
$uri = Get-AzureWinRMUri -ServiceName $ServiceNameDCTier -Name "SPDC01"
 
# Using generated certs – use helper function to download and install generated cert.
InstallWinRMCert $ServiceNameDCTier "SPDC01"
 
# Use native PowerShell Cmdlet to execute a script block on the remote virtual machine


Invoke-Command -ConnectionUri $uri.ToString() -Credential $credential -ScriptBlock {
    $logLabel = $((get-date).ToString("yyyyMMddHHmmss"))
    $logPath = "$env:TEMP\init-webservervm_webserver_install_log_$logLabel.txt"
    # Format Datadisk    
    Initialize-Disk -Number 2 -PartitionStyle GPT 
    New-Partition -DiskNumber 2 -UseMaximumSize -DriveLetter F | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Force
    #Dcpromo Create Forest
    Import-Module -Name ServerManager
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -LogPath $logPath
    $secpassword = ConvertTo-SecureString "pass@word1" -AsPlainText -Force
    Install-ADDSForest -DomainName "contoso.com" -DatabasePath "f:\NTDS" -SysvolPath "f:\SYSVOL" -LogPath "f:\Logs" -SafeModeAdministratorPassword $secpassword -InstallDns
} 


#Create SQL VM - join dc
New-AzureVMConfig -Name "SQL01" -InstanceSize Large -ImageName $sqlImage.ImageName |
    Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $adminname –Password $adminpassword -JoinDomain $domainjoin -Domain $domain -DomainUserName $adminname -DomainPassword $adminpassword |
    Set-AzureSubnet -SubnetNames $SubnetSPFarmTier |
    New-AzureVM -ServiceName $ServiceNameSQLTier -AffinityGroup $AffinityGroup -VNetName $VNETName

#Create SharePoint VM - join dc
New-AzureVMConfig -Name "SP01" -InstanceSize Large -ImageName $spImage.ImageName |
    Add-AzureProvisioningConfig -WindowsDomain -AdminUsername $adminname –Password $adminpassword -JoinDomain $domainjoin -Domain $domain -DomainUserName $adminname -DomainPassword $adminpassword |
    Set-AzureSubnet -SubnetNames $SubnetSPFarmTier |
    New-AzureVM -ServiceName $ServiceNameSPTier -AffinityGroup $AffinityGroup -VNetName $VNETName





