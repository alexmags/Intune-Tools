param(
    [string]$id,
    [string]$password
)

# Make code debuggable
$ErrorActionPreference = "Stop"
Set-StrictMode -Version latest

function get-moduleIfNotInstalled ($modulename) {
    if (!(get-module $modulename -listavailable)) {
        write-host "Installing $modulename into current user scope"
        Install-Module -name $modulename -Scope 'CurrentUser' -Confirm:$false -Force
        get-Module -name $modulename -ListAvailable # log the versions of modules availble
    }
    else {
        write-host "$modulename already installed"
    }
    import-Module -Name $modulename
    write-host "$modulename imported"
} 

get-moduleIfNotInstalled -modulename azurerm.profile

# https://docs.microsoft.com/en-us/office365/enterprise/powershell/connect-to-all-office-365-services-in-a-single-windows-powershell-window
$o365creds = $null
# Build cred object from params or prompt
if ($password -and $id) {
    $secpasswd = ConvertTo-SecureString $password -AsPlainText -Force -ErrorAction SilentlyContinue
    $o365creds = New-Object System.Management.Automation.PSCredential ($id, $secpasswd)
    write-host "Running from $PSScriptRoot using ID: $id"
}
elseif ($env:SYSTEM_TEAMPROJECT) {
    write-error "This is a Azure DevOps deployment and ID or password parameters missing."    
}

# Login to azure Resource Manager if not already logged in
try
    {
    $context = Get-AzureRmContext
    }
catch
{
    if ([string]::IsNullOrEmpty($o365creds))
        {
        login-azurermaccount
        }
    else{
        login-azurermaccount -Credential $o365creds
    }
    $context = Get-AzureRmContext
}

# build API token
$context = Get-AzureRmContext
$tenantId = $context.Tenant.Id
$refreshToken = @($context.TokenCache.ReadItems() | where {$_.tenantId -eq $tenantId -and $_.ExpiresOn -gt (Get-Date)})[0].RefreshToken
$body = "grant_type=refresh_token&refresh_token=$($refreshToken)&resource=74658136-14ec-4630-ad9b-26e160ff0fc6"
$apiToken = Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'

# Build header with content-type
$header = @{
'Authorization' = 'Bearer ' + $apiToken.access_token
'X-Requested-With'= 'XMLHttpRequest'
'x-ms-client-request-id'= [guid]::NewGuid()
'x-ms-correlation-id' = [guid]::NewGuid()
'Content-Type'='application/json'
}

$evaluateURL="https://main.iam.ad.ext.azure.com/api/Policies/Evaluate"
$evaulateRequestJSON= Get-Content -Path '.\evaluateRequest.json' # load template json relative to here
$evaulateRequestObject= $evaulateRequestJSON | ConvertFrom-JSON

# Build array of test cases
$evaulateRequestObjects=@()

# Build case 1 android 
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.android=$true
$evaulateRequestObjects+=$evaulateRequestObject

# Build case 1 ios 
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.android=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.ios=$true
$evaulateRequestObjects+=$evaulateRequestObject

# Build case 2 Windows PC
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.android=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.ios=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.windows=$true
$evaulateRequestObjects+=$evaulateRequestObject

# Build case 3 MacOS
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.android=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.ios=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.windows=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.macOs=$true
$evaulateRequestObjects+=$evaulateRequestObject

# Build case 4 Windows Phone
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.android=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.ios=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.windows=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.macOs=$false
$evaulateRequestObject.conditions.conditions.devicePlatforms.included.windowsPhone=$false
$evaulateRequestObjects+=$evaulateRequestObject

# Run through test cases
foreach ($evaulateRequest in $evaulateRequestObjects){

    $evaulateRequestJSON=$evaulateRequest | ConvertTo-Json -Depth 10
    $policies = Invoke-RestMethod –Uri $evaluateURL –Headers $header –Method POST -ErrorAction Stop -Body $evaulateRequestJSON
    ForEach ($policy in $policies)
    {
        Write-Output "$($policy.policyName) is $($policy.applied)"
        
        # Do some pester tests here....
        
        if ($policy.applied)
        {
            Write-Output $policy.policyName
        
            $policy.controls | Format-List
            $policy.sessionControls | Format-List
        }

    }
}

# reporting
$policies | select policyname,applied
$policies | Where-Object {$_.applied -eq $true} | select -ExpandProperty controls