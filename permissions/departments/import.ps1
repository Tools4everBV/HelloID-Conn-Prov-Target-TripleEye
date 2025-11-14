####################################################################
# HelloID-Conn-Prov-Target-TripleEye-Permissions-Groups-Import
# PowerShell V2
####################################################################

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
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
        }
        catch {
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
    Write-Information 'Starting TripleEye permission group entitlement import'

    $headers = @{
        token         = "$($actionContext.Configuration.Token)"
        'X-Signature' = Get-SignatureForEmptyBody
    }

    # get permissions
    $splatGetPermissions = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/departments"
        Method  = 'GET'
        Headers = $headers
    }
    $importedPermissions = Invoke-RestMethod @splatGetPermissions

    # get accounts with pagination and imported permissions
    $skip = 250
    do {
        $filter = @{ skip = $skip } | ConvertTo-Json -Compress
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)

        $splatGetEmployees = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees?filter=$encodedFilter"
            Method  = 'GET'
            Headers = $headers
        }
        $importedAccounts = Invoke-RestMethod @splatGetEmployees
        $count = $importedAccounts.count
        $skip += 250

        $importedAccountsWithPermissions = @()
        foreach ($importedAccount in $importedAccounts) {
            $splatGetEmployeesWithPermissions = @{
                Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees/$($importedAccount.id)/getPermissions"
                Method  = 'GET'
                Headers = $headers
            }
            $importedAccountsWithPermissions += Invoke-RestMethod @splatGetEmployeesWithPermissions
        }

        foreach ($importedPermission in $importedPermissions) {
            $accountReferences = @($importedAccountsWithPermissions | Where-Object { $_.departments -contains $importedPermission.id } | Select-Object -ExpandProperty id)

            $permission = @{
                PermissionReference = @{
                    Reference = $importedPermission.id
                }
                Description         = "$($importedPermission.name)"
                DisplayName         = "$($importedPermission.name)"
                AccountReferences   = $accountReferences
            }

            $accountsBatchSize = 500
            $numberOfAccounts = $accountReferences.count

            if ($numberOfAccounts -gt 0) {
                $batches = 0..($numberOfAccounts - 1) | Group-Object { [math]::Floor($_ / $accountsBatchSize) }

                foreach ($batch in $batches) {
                    $permission.AccountReferences = [array]($batch.Group | ForEach-Object { @($accountReferences[$_]) })
                    Write-Output $permission
                }
            }
        }
    }
    while ($count -eq 250)
    Write-Information 'TripleEye permission group entitlement import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TripleEyeError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import TripleEye permission group entitlements. Error: $($errorObj.FriendlyMessage)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import TripleEye permission group entitlements. Error: $($ex.Exception.Message)"
    }
}