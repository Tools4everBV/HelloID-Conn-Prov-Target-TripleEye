#################################################
# HelloID-Conn-Prov-Target-TripleEye-Import
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-TripleEyeError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            $httpErrorObj.FriendlyMessage = $errorDetailsObject.error.message
        } catch {
            $httpErrorObj.FriendlyMessage = "Error: [$($httpErrorObj.ErrorDetails)] [$($_.Exception.Message)]"
        }
        Write-Output $httpErrorObj
    }
}

function Get-Signature {
    param(
        $bodyJson
    )
    $timestamp = [System.DateTimeOffset]::new((Get-Date)).ToUnixTimeSeconds().ToString()
    $message = $timestamp + '.' + $bodyJson
    $hmacsha = [System.Security.Cryptography.HMACSHA256]::new(  )
    $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($actionContext.Configuration.SignatureCode)
    $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
    $signature = -join $signature.ForEach('ToString', 'x2')
    $signatureHeader = 't=' + $timestamp + ',' + 'v1=' + $signature
    return $signatureHeader
}

function Get-SignatureForEmptyBody () {
    $body = @{}
    $bodyJson = $body | ConvertTo-Json -Compress
    return Get-Signature ($bodyJson)
}
#endregion

try {
    Write-Information 'Starting TripleEye account entitlement import'

    $headers = @{
        token         = "$($actionContext.Configuration.Token)"
        'X-Signature' = Get-SignatureForEmptyBody
    }

    $splatGetEmployees = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees"
        Method  = 'GET'
        Headers = $headers
    }
    $importedAccounts = Invoke-RestMethod @splatGetEmployees


    if ($actionContext.DryRun) {
        $importedAccounts = $importedAccounts | Select-Object -First 10
    }

    foreach ($importedAccount in $importedAccounts) {
        # Making sure only fieldMapping fields are imported
        $data = @{}
        foreach ($field in $actionContext.ImportFields) {
            $data.$field = $importedAccount.$field
        }

        # Set Enabled based on importedAccount status
        $isEnabled = $false
        if ($null -ne $importedAccount.accessDisabled) {
            $isEnabled = -not($importedAccount.accessDisabled)
        }

        # Make sure the displayName has a value
        $displayName = "$($importedAccount.name)".trim()
        if ([string]::IsNullOrEmpty($displayName)) {
            $displayName = $importedAccount.id
        }

        # Make sure the userName has a value
        $username = "$($importedAccount.email)".trim()
        if ([string]::IsNullOrEmpty($importedAccount.email)) {
            $username = $importedAccount.Id
        }

        # Return the result
        Write-Output @{
            AccountReference = $importedAccount.id
            displayName      = $displayName
            UserName         = $username
            Enabled          = $isEnabled
            Data             = $data
        }
    }
    Write-Information 'TripleEye account entitlement import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TripleEyeError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import TripleEye account entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import TripleEye account entitlements. Error: $($ex.Exception.Message)"
    }
}