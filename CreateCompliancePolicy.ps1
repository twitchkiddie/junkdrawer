#Requires -Modules  MSAL.PS

function Invoke-GetVersionNumbers{
    $Windows10HTML = Invoke-RestMethod 'https://docs.microsoft.com/en-us/windows/release-health/release-information'
    $Windows10 = $Windows10HTML | Select-String '(?smi)<td>([^<]*)<\/td>' -AllMatches

    $Windows11HTML = Invoke-RestMethod 'https://docs.microsoft.com/en-us/windows/release-health/windows11-release-information'
    $Windows11 = $Windows11HTML | Select-String '(?smi)<td>([^<]*)<\/td>' -AllMatches
    $Versions = @(
        [pscustomobject]@{OS='Windows 11';MajorVersion=$Windows11.Matches[0].Groups[1].Value.SubString(0,4);Build=$Windows11.Matches[3].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[0].Groups[1].Value;Build=$Windows10.Matches[3].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[6].Groups[1].Value;Build=$Windows10.Matches[9].Groups[1].Value}
        [pscustomobject]@{OS='Windows 10';MajorVersion=$Windows10.Matches[12].Groups[1].Value;Build=$Windows10.Matches[15].Groups[1].Value}
 
    )
    return $Versions
}

function Get-AuthTokenSP {
    $AppId = ''
    $AppSecret = ''
    $Scope = "https://graph.microsoft.com/.default"
    $TenantName = ""

    $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"

    # Add System.Web for urlencode
    Add-Type -AssemblyName System.Web

    # Create body
    $Body = @{
        client_id = $AppId
	    client_secret = $AppSecret
	    scope = "offline_access $($Scope)"
	    grant_type = 'client_credentials'
    }

    # Splat the parameters for Invoke-Restmethod for cleaner code
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        # Create string by joining bodylist with '&'
        Body = $Body
        Uri = $Url
    }

    # Request the token!
    $Request = Invoke-RestMethod @PostSplat

    if($Request.access_token){

    # Creating header for Authorization token

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer "+$Request.access_token
        'ExpiresOn'= $Request.expires_in
        }

    return $authHeader
    #Return $Request.access_token
    }

    else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

    }
}

function Invoke-CreateComplianceJSON($description,$displayName,$VersionNumber){
$JSON = @"
{
    "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    "roleScopeTagIds": [
        "0"
    ],
    "description": "$($description)",
    "displayName": "$($displayName)",
    "version": 1,
    "passwordRequired": false,
    "passwordBlockSimple": false,
    "passwordRequiredToUnlockFromIdle": false,
    "passwordMinutesOfInactivityBeforeLock": null,
    "passwordExpirationDays": null,
    "passwordMinimumLength": null,
    "passwordMinimumCharacterSetCount": null,
    "passwordRequiredType": "deviceDefault",
    "passwordPreviousPasswordBlockCount": null,
    "requireHealthyDeviceReport": false,
    "osMinimumVersion": "$($VersionNumber)",
    "osMaximumVersion": null,
    "mobileOsMinimumVersion": null,
    "mobileOsMaximumVersion": null,
    "earlyLaunchAntiMalwareDriverEnabled": false,
    "bitLockerEnabled": false,
    "secureBootEnabled": false,
    "codeIntegrityEnabled": false,
    "storageRequireEncryption": false,
    "activeFirewallRequired": false,
    "defenderEnabled": false,
    "defenderVersion": null,
    "signatureOutOfDate": false,
    "rtpEnabled": false,
    "antivirusRequired": false,
    "antiSpywareRequired": false,
    "deviceThreatProtectionEnabled": false,
    "deviceThreatProtectionRequiredSecurityLevel": "unavailable",
    "configurationManagerComplianceRequired": false,
    "tpmRequired": false,
    "deviceCompliancePolicyScript": null,
    "validOperatingSystemBuildRanges": [],
    "scheduledActionsForRule": [
        {
            "id": "e2ac16f1-a55b-43df-99ee-88548bb8bb5f",
            "ruleName": null,
            "scheduledActionConfigurations": [
                {
                    "id": "bfa63053-8e09-462a-8e22-0c5caceabe48",
                    "gracePeriodHours": 720,
                    "actionType": "block",
                    "notificationTemplateId": "00000000-0000-0000-0000-000000000000",
                    "notificationMessageCCList": []
                },
                {
                    "id": "efc08519-2fde-44c0-bd59-b05569bb7c82",
                    "gracePeriodHours": 24,
                    "actionType": "notification",
                    "notificationTemplateId": "c9a89382-284e-4c2e-8c09-ba2dafa215c8",
                    "notificationMessageCCList": []
                }
            ]
        }
    ]
}
"@

return $JSON
}
$WindowsVersions = Invoke-GetVersionNumbers

foreach($WindowsVersion in $WindowsVersions)
{
    Write-Host "$($WindowsVersion.OS) OS Build $($WindowsVersion.MajorVersion) Version Requirement - 10.0.$($WindowsVersion.Build)"
    $PolicyJson = Invoke-CreateComplianceJSON `
    -description "This policy was Autocreated $(Get-date) and is to require a minimum version number" `
    -displayName "$($WindowsVersion.OS) OS Build $($WindowsVersion.MajorVersion) Version Requirement - 10.0.$($WindowsVersion.Build)" `
    -VersionNumber "10.0.$($WindowsVersion.Build)"

    $graphApiVersion = "v1.0"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $(Get-AuthTokenSP) -Method Post -Body $PolicyJson -ContentType "application/json"
}

