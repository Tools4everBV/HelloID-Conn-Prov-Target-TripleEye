#################################################
# HelloID-Conn-Prov-Target-TripleEye-Create
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
    $timestamp = [System.DateTimeOffset]::new((Get-Date)).ToUnixTimeSeconds().ToString();
    $message = $timestamp + '.' + $bodyJson
    $hmacsha = [System.Security.Cryptography.HMACSHA256]::new(  )
    $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($actionContext.Configuration.SignatureCode)
    $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
    $signature = -join $signature.ForEach('ToString', 'x2')
    $signatureHeader = 't=' + $timestamp + "," + 'v1=' + $signature
    return $signatureHeader
}

function Get-SignatureForEmptyBody () {
    $body = @{}
    $bodyJson = $body | ConvertTo-Json -Compress
    return Get-Signature ($bodyJson)
}
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    $headers = @{
        token         = "$($actionContext.Configuration.Token)"
        'X-Signature' = Get-SignatureForEmptyBody
    }

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue
        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }
        $splatCorrelateEmployee = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees/findOne?filter[where][$correlationField]=$([uri]::EscapeDataString($correlationValue))"
            Method  = 'GET'
            Headers = $headers
        }
        try {
            $correlatedAccount = Invoke-RestMethod @splatCorrelateEmployee
        } catch {
            if (-not ($_.Exception.Response.StatusCode -eq 404)) {
                throw $_
            }
        }
    }

    if ($null -eq $correlatedAccount) {
        $action = 'CreateAccount'
    } else {
        $action = 'CorrelateAccount'
    }

    # Process
    switch ($action) {
        'CreateAccount' {
            if ($null -ne $actionContext.Data.accessDisabled) {
                $actionContext.Data.accessDisabled = [bool]::Parse($actionContext.Data.accessDisabled)
            }
            $headers['X-Signature'] = Get-Signature ($actionContext.Data | ConvertTo-Json -Compress)
            $splatCreateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees"
                Method      = 'POST'
                Body        = $actionContext.Data | ConvertTo-Json -Compress
                ContentType = 'application/json; charset=utf-8'
                Headers     = $headers
            }


            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating TripleEye account'
                $createdAccount = Invoke-RestMethod @splatCreateParams
                $outputContext.Data = $createdAccount
                $outputContext.AccountReference = $createdAccount.Id
            } else {
                Write-Information '[DryRun] Create and correlate TripleEye account, will be executed during enforcement'
            }
            $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating TripleEye account'
            $outputContext.Data = $correlatedAccount
            $outputContext.AccountReference = $correlatedAccount.Id
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }

    $outputContext.Success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TripleEyeError -ErrorObject $ex
        $auditMessage = "Could not create or correlate TripleEye account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not create or correlate TripleEye account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}