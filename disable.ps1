##################################################
# HelloID-Conn-Prov-Target-TripleEye-Disable
# PowerShell V2
##################################################

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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    Write-Information 'Verifying if a TripleEye account exists'
    $headers = @{
        token         = "$($actionContext.Configuration.Token)"
        'X-Signature' = Get-SignatureForEmptyBody
    }
    $splatGetEmployee = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees/findOne?filter[where][id]=$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $correlatedAccount = Invoke-RestMethod @splatGetEmployee
    } catch {
        if (-not  $_.Exception.Response.StatusCode -eq 404) {
            throw $_
        }
    }

    if ($null -ne $correlatedAccount) {
        $action = 'DisableAccount'
    } else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'DisableAccount' {
            Write-Information "Disabling TripleEye account with accountReference: [$($actionContext.References.Account)]"
            $bodyJson = @{
                employeeId     = $actionContext.References.Account
                accessDisabled = $true
                endStamp       = (Get-Date).AddDays(-1).ToUniversalTime().ToString('o')
            } | ConvertTo-Json -Compress
            $headers['X-Signature'] = Get-Signature ($bodyJson)
            $splatUpdateParams = @{
                Uri         = "$($actionContext.Configuration.BaseUrl)/$($actionContext.Configuration.HookId)/organisation/employees"
                Method      = 'PUT'
                Body        = $bodyJson
                ContentType = 'application/json; charset=utf-8'
                Headers     = $headers
            }
            if (-not($actionContext.DryRun -eq $true)) {
                $null = Invoke-RestMethod @splatUpdateParams
            } else {
                Write-Information "[DryRun] Disable TripleEye account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'Disable account was successful'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "TripleEye account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "TripleEye account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-TripleEyeError -ErrorObject $ex
        $auditMessage = "Could not disable TripleEye account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not disable TripleEye account. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}