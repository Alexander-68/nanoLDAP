#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$HostName = '127.0.0.1',
    [int]$HttpPort = 18080,
    [int]$HttpsPort = 18443,
    [int]$LdapPort = 1389,
    [int]$LdapsPort = 1636,
    [string]$BaseDn = 'dc=example,dc=com',
    [string]$WorkingDirectory = (Get-Location).Path,
    [string]$LdapsearchPath = '',
    [switch]$SkipServerStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Invoke-TestRequest {
    param(
        [string]$Uri,
        [string]$Method = 'Get',
        [object]$Body = $null,
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = $null
    )

    $params = @{
        Uri                 = $Uri
        Method              = $Method
        SkipCertificateCheck = $true
        SkipHttpErrorCheck  = $true
    }
    if ($null -ne $Body) {
        $params.Body = $Body
    }
    if ($null -ne $WebSession) {
        $params.WebSession = $WebSession
    }
    Invoke-WebRequest @params
}

function Get-ResponseText {
    param([object]$Content)

    if ($Content -is [byte[]]) {
        return [System.Text.Encoding]::ASCII.GetString($Content)
    }
    return [string]$Content
}

function Wait-ServerReady {
    param([int]$Port)

    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri "http://${HostName}:$Port/ca.crt" -SkipHttpErrorCheck
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
        }
        Start-Sleep -Milliseconds 250
    }

    throw "NanoLDAP did not become ready on http://${HostName}:$Port within 20 seconds."
}

function Start-NanoLDAP {
    param([string]$RootPath)

    $dbPath = Join-Path $RootPath 'nanoldap.db'
    $auditPath = Join-Path $RootPath 'audit.log'
    $certPath = Join-Path $RootPath 'cert.pem'
    $keyPath = Join-Path $RootPath 'key.pem'

    $argumentList = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @(
        'run',
        './cmd/nanoldap',
        '--bind-addr', $HostName,
        '--db-path', $dbPath,
        '--audit-log', $auditPath,
        '--cert-file', $certPath,
        '--key-file', $keyPath,
        '--http-port', $HttpPort.ToString(),
        '--https-port', $HttpsPort.ToString(),
        '--ldap-port', $LdapPort.ToString(),
        '--ldaps-port', $LdapsPort.ToString()
    )) {
        [void]$argumentList.Add($value)
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'go'
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $argumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    Wait-ServerReady -Port $HttpPort
    return @{
        Process = $process
        RootPath = $RootPath
    }
}

function Get-LdapsearchExecutable {
    $cachedCommand = Get-Variable -Name LdapsearchExecutable -Scope Script -ErrorAction SilentlyContinue
    if ($cachedCommand -and $cachedCommand.Value) {
        return $script:LdapsearchExecutable
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($LdapsearchPath) {
        [void]$candidates.Add($LdapsearchPath)
    }
    if ($env:LDAPSEARCH) {
        [void]$candidates.Add($env:LDAPSEARCH)
    }
    if ($IsWindows) {
        [void]$candidates.Add('C:\OpenLDAP-2.6.9\bin\ldapsearch.exe')
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $script:LdapsearchExecutable = (Resolve-Path -LiteralPath $candidate).Path
            return $script:LdapsearchExecutable
        }
    }

    try {
        $script:LdapsearchExecutable = (Get-Command ldapsearch -ErrorAction Stop).Source
        return $script:LdapsearchExecutable
    }
    catch {
        return $null
    }
}

function Stop-NanoLDAP {
    param([hashtable]$State)

    if ($null -eq $State -or $null -eq $State.Process) {
        return
    }

    if (-not $State.Process.HasExited) {
        $State.Process.Kill($true)
        $null = $State.Process.WaitForExit(5000)
    }
}

function New-LdapTestConnection {
    param(
        [int]$Port,
        [bool]$UseSsl,
        [System.DirectoryServices.Protocols.AuthType]$AuthType,
        [System.Net.NetworkCredential]$Credential = $null,
        [string]$ExpectedThumbprint = ''
    )

    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($HostName, $Port, $false, $false)
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
    $connection.AuthType = $AuthType
    $connection.Timeout = [TimeSpan]::FromSeconds(5)
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.SessionOptions.AutoReconnect = $false

    if ($UseSsl) {
        $connection.SessionOptions.SecureSocketLayer = $true
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $callback = [System.DirectoryServices.Protocols.VerifyServerCertificateCallback]{
            param($conn, $certificate)
            $candidate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
            return $candidate.Thumbprint -eq $ExpectedThumbprint
        }
        $connection.SessionOptions.VerifyServerCertificate = $callback
        $ErrorActionPreference = $oldPreference
    }

    if ($null -ne $Credential) {
        $connection.Credential = $Credential
    }

    return $connection
}

function Test-WebEndpoints {
    Write-Step 'Testing HTTP/HTTPS certificate retrieval and RBAC'

    $httpCert = Invoke-WebRequest -Uri "http://${HostName}:$HttpPort/ca.crt" -SkipHttpErrorCheck
    $httpsCert = Invoke-WebRequest -Uri "https://${HostName}:$HttpsPort/ca.crt" -SkipCertificateCheck -SkipHttpErrorCheck
    $httpCertText = Get-ResponseText -Content $httpCert.Content
    $httpsCertText = Get-ResponseText -Content $httpsCert.Content
    Assert-True ($httpCert.StatusCode -eq 200) 'HTTP /ca.crt did not return 200.'
    Assert-True ($httpsCert.StatusCode -eq 200) 'HTTPS /ca.crt did not return 200.'
    Assert-True ($httpCertText -match '-----BEGIN CERTIFICATE-----') 'HTTP /ca.crt did not contain a PEM certificate.'
    Assert-True ($httpsCertText -match '-----BEGIN CERTIFICATE-----') 'HTTPS /ca.crt did not contain a PEM certificate.'

    $guestSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $guestLogin = Invoke-TestRequest -Uri "https://${HostName}:$HttpsPort/login" -Method 'Post' -Body @{ username = 'guest'; password = 'guest' } -WebSession $guestSession
    Assert-True ($guestLogin.StatusCode -eq 403) 'Guest login should be rejected from the web UI.'

    $adminSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $adminLogin = Invoke-TestRequest -Uri "https://${HostName}:$HttpsPort/login" -Method 'Post' -Body @{ username = 'admin'; password = 'admin' } -WebSession $adminSession
    Assert-True ($adminLogin.StatusCode -in 200, 303) 'Admin login should succeed.'
    $usersPage = Invoke-WebRequest -Uri "https://${HostName}:$HttpsPort/users" -SkipCertificateCheck -WebSession $adminSession
    Assert-True ($usersPage.StatusCode -eq 200) 'Admin session could not access /users.'
    $null = Invoke-TestRequest -Uri "https://${HostName}:$HttpsPort/logout" -Method 'Post' -WebSession $adminSession

    Write-Step 'Testing global web session limit'
    $sessions = [System.Collections.Generic.List[Microsoft.PowerShell.Commands.WebRequestSession]]::new()
    foreach ($index in 1..4) {
        $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $response = Invoke-TestRequest -Uri "https://${HostName}:$HttpsPort/login" -Method 'Post' -Body @{ username = 'admin'; password = 'admin' } -WebSession $webSession
        [void]$sessions.Add($webSession)
        if ($index -lt 4) {
            Assert-True ($response.StatusCode -in 200, 303) "Admin login $index should succeed."
        }
        else {
            Assert-True ($response.StatusCode -eq 429) 'The fourth concurrent admin login should be rejected.'
        }
    }
}

function Invoke-LdapSearch {
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,
        [string]$Base,
        [string]$Filter,
        [System.DirectoryServices.Protocols.SearchScope]$Scope,
        [string[]]$Attributes = @()
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new($Base, $Filter, $Scope, $Attributes)
    return [System.DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($request)
}

function Invoke-LdapsearchCommand {
    param(
        [string[]]$Arguments,
        [string]$CaCertPath = '',
        [switch]$SkipCertificateValidation
    )

    $ldapsearch = Get-LdapsearchExecutable
    if (-not $ldapsearch) {
        throw 'ldapsearch was not found. Add it to PATH, set $env:LDAPSEARCH, or pass -LdapsearchPath.'
    }
    $previousNoInit = $env:LDAPNOINIT

    try {
        $env:LDAPNOINIT = '1'
        $effectiveArguments = [System.Collections.Generic.List[string]]::new()
        foreach ($value in @('-o', 'nettimeout=5')) {
            [void]$effectiveArguments.Add($value)
        }
        if ($SkipCertificateValidation) {
            foreach ($value in @('-o', 'tls_reqcert=never')) {
                [void]$effectiveArguments.Add($value)
            }
        }
        foreach ($argument in $Arguments) {
            [void]$effectiveArguments.Add($argument)
        }

        $output = & $ldapsearch @effectiveArguments 2>&1 | Out-String
        return @{
            ExitCode = $LASTEXITCODE
            Output   = $output
        }
    }
    finally {
        if ($null -eq $previousNoInit) {
            Remove-Item Env:LDAPNOINIT -ErrorAction SilentlyContinue
        }
        else {
            $env:LDAPNOINIT = $previousNoInit
        }
    }
}

function Test-LdapsearchProtocol {
    param(
        [string]$Name,
        [string]$Scheme,
        [int]$Port,
        [string]$CaCertPath = ''
    )

    $uri = "${Scheme}://${HostName}:$Port"
    $userDn = "uid=user,ou=people,$BaseDn"
    $adminDn = "uid=admin,ou=people,$BaseDn"
    $guestDn = "uid=guest,ou=people,$BaseDn"

    Write-Step "Testing $Name with ldapsearch"

    $anonymousRoot = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
        '-x', '-LLL',
        '-H', $uri,
        '-s', 'base',
        '-b', '',
        '(objectClass=*)',
        'namingContexts',
        'supportedLDAPVersion'
    )
    Assert-True ($anonymousRoot.ExitCode -eq 0) "$Name anonymous Root DSE query failed: $($anonymousRoot.Output)"
    Assert-True ($anonymousRoot.Output -match [regex]::Escape("namingContexts: $BaseDn")) "$Name Root DSE output did not contain namingContexts."

    $anonymousRestricted = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
        '-x', '-LLL',
        '-H', $uri,
        '-b', "ou=people,$BaseDn",
        '(objectClass=inetOrgPerson)',
        'uid'
    )
    Assert-True ($anonymousRestricted.ExitCode -ne 0) "$Name anonymous subtree search should fail."
    Assert-True ($anonymousRestricted.Output -match 'Insufficient access|result:\s*50|LDAP_INSUFFICIENT_ACCESS') "$Name anonymous restriction error was not detected."

    Start-Sleep -Seconds 11
    $userSearch = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
        '-x', '-LLL',
        '-H', $uri,
        '-D', $userDn,
        '-w', 'user',
        '-b', "ou=groups,$BaseDn",
        "(|(member=$userDn)(uniqueMember=$userDn)(memberUid=user))",
        'cn'
    )
    Assert-True ($userSearch.ExitCode -eq 0) "$Name user group search failed: $($userSearch.Output)"
    Assert-True ($userSearch.Output -match 'cn:\s+users') "$Name user group search did not return the users group."

    $adminSearch = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
        '-x', '-LLL',
        '-H', $uri,
        '-D', $adminDn,
        '-w', 'admin',
        '-b', "ou=people,$BaseDn",
        '(uid=guest)',
        'uid'
    )
    Assert-True ($adminSearch.ExitCode -eq 0) "$Name admin search failed: $($adminSearch.Output)"
    Assert-True ($adminSearch.Output -match 'uid:\s+guest') "$Name admin search did not return guest."

    $guestSearch = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
        '-x', '-LLL',
        '-H', $uri,
        '-D', $guestDn,
        '-w', 'guest',
        '-b', "ou=people,$BaseDn",
        '(uid=admin)',
        'uid'
    )
    Assert-True ($guestSearch.ExitCode -eq 0) "$Name guest search failed unexpectedly: $($guestSearch.Output)"
    Assert-True ($guestSearch.Output -notmatch 'uid:\s+admin') "$Name guest search should not return admin."

    Write-Step "Testing $Name bind rate limiting with ldapsearch"
    Start-Sleep -Seconds 11
    $fourthRateLimited = $false
    foreach ($attempt in 1..4) {
        $badBind = Invoke-LdapsearchCommand -CaCertPath $CaCertPath -SkipCertificateValidation:($Scheme -eq 'ldaps') -Arguments @(
            '-x', '-LLL',
            '-H', $uri,
            '-D', $userDn,
            '-w', 'wrong',
            '-s', 'base',
            '-b', '',
            '(objectClass=*)',
            'namingContexts'
        )
        if ($attempt -lt 4) {
            Assert-True ($badBind.ExitCode -ne 0) "$Name bad bind attempt $attempt should fail."
            Assert-True ($badBind.Output -match 'Invalid credentials|result:\s*49') "$Name bad bind attempt $attempt should fail with invalid credentials."
        }
        else {
            $fourthRateLimited = $badBind.Output -match 'busy|result:\s*51|LDAP_BUSY'
        }
    }
    Assert-True $fourthRateLimited "$Name fourth bad bind should be rate limited."
}

function Test-LdapsearchEndpoints {
    param([string]$CaCertPath)

    Test-LdapsearchProtocol -Name 'LDAP' -Scheme 'ldap' -Port $LdapPort
    Start-Sleep -Seconds 11
    Test-LdapsearchProtocol -Name 'LDAPS' -Scheme 'ldaps' -Port $LdapsPort -CaCertPath $CaCertPath
}

function Test-LdapEndpoints {
    param(
        [string]$ExpectedThumbprint,
        [string]$CaCertPath = ''
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $targets = @(
        @{ Name = 'LDAP'; Port = $LdapPort; UseSsl = $false }
    )

    foreach ($target in $targets) {
        Write-Step "Testing $($target.Name) anonymous bind and Root DSE"
        $anonymous = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Anonymous) -ExpectedThumbprint $ExpectedThumbprint
        try {
            $anonymous.Bind()
            $root = Invoke-LdapSearch -Connection $anonymous -Base '' -Filter '(objectClass=*)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Base) -Attributes @('namingContexts', 'supportedLDAPVersion')
            Assert-True ($root.Entries.Count -eq 1) "$($target.Name) Root DSE search should return one entry."
            Assert-True ($root.Entries[0].Attributes['namingContexts'][0] -eq $BaseDn) "$($target.Name) Root DSE namingContexts did not match the configured base DN."

            $anonymousRestrictionTriggered = $false
            try {
                [void](Invoke-LdapSearch -Connection $anonymous -Base "ou=people,$BaseDn" -Filter '(objectClass=inetOrgPerson)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Subtree))
            }
            catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
                $anonymousRestrictionTriggered = $_.Exception.Response.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::InsufficientAccessRights
            }
            Assert-True $anonymousRestrictionTriggered "$($target.Name) anonymous subtree search should be denied."
        }
        finally {
            $anonymous.Dispose()
        }

        Start-Sleep -Seconds 11
        Write-Step "Testing $($target.Name) authenticated and scoped searches"
        $userCredential = [System.Net.NetworkCredential]::new("uid=user,ou=people,$BaseDn", 'user')
        $userConnection = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Basic) -Credential $userCredential -ExpectedThumbprint $ExpectedThumbprint
        try {
            $userConnection.Bind()
            $groupResponse = Invoke-LdapSearch -Connection $userConnection -Base "ou=groups,$BaseDn" -Filter "(|(member=uid=user,ou=people,$BaseDn)(uniqueMember=uid=user,ou=people,$BaseDn)(memberUid=user))" -Scope ([System.DirectoryServices.Protocols.SearchScope]::Subtree) -Attributes @('cn')
            Assert-True ($groupResponse.Entries.Count -eq 1) "$($target.Name) user group search should return exactly one group."
            Assert-True ($groupResponse.Entries[0].Attributes['cn'][0] -eq 'users') "$($target.Name) user group search should resolve the users group."
        }
        finally {
            $userConnection.Dispose()
        }

        $adminCredential = [System.Net.NetworkCredential]::new("uid=admin,ou=people,$BaseDn", 'admin')
        $adminConnection = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Basic) -Credential $adminCredential -ExpectedThumbprint $ExpectedThumbprint
        try {
            $adminConnection.Bind()
            $adminSearch = Invoke-LdapSearch -Connection $adminConnection -Base "ou=people,$BaseDn" -Filter '(uid=guest)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Subtree) -Attributes @('uid')
            Assert-True ($adminSearch.Entries.Count -eq 1) "$($target.Name) admin search should find guest."
            Assert-True ($adminSearch.Entries[0].Attributes['uid'][0] -eq 'guest') "$($target.Name) admin search result should be guest."
        }
        finally {
            $adminConnection.Dispose()
        }

        $guestCredential = [System.Net.NetworkCredential]::new("uid=guest,ou=people,$BaseDn", 'guest')
        $guestConnection = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Basic) -Credential $guestCredential -ExpectedThumbprint $ExpectedThumbprint
        try {
            $guestConnection.Bind()
            $guestSearch = Invoke-LdapSearch -Connection $guestConnection -Base "ou=people,$BaseDn" -Filter '(uid=admin)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Subtree) -Attributes @('uid')
            Assert-True ($guestSearch.Entries.Count -eq 0) "$($target.Name) guest search for admin should return no entries."
        }
        finally {
            $guestConnection.Dispose()
        }

        Start-Sleep -Seconds 11
        Write-Step "Testing $($target.Name) idle timeout"
        $idleConnection = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Basic) -Credential $userCredential -ExpectedThumbprint $ExpectedThumbprint
        try {
            $idleConnection.Bind()
            Start-Sleep -Seconds 6
            $timeoutTriggered = $false
            try {
                [void](Invoke-LdapSearch -Connection $idleConnection -Base '' -Filter '(objectClass=*)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Base))
            }
            catch {
                $timeoutTriggered = $true
            }
            Assert-True $timeoutTriggered "$($target.Name) connection should be dropped after the idle timeout."
        }
        finally {
            $idleConnection.Dispose()
        }

        Write-Step "Testing $($target.Name) bind rate limiting"
        Start-Sleep -Seconds 11
        $fourthRateLimited = $false
        foreach ($attempt in 1..4) {
            $badCredential = [System.Net.NetworkCredential]::new("uid=user,ou=people,$BaseDn", 'wrong')
            $badConnection = New-LdapTestConnection -Port $target.Port -UseSsl $target.UseSsl -AuthType ([System.DirectoryServices.Protocols.AuthType]::Basic) -Credential $badCredential -ExpectedThumbprint $ExpectedThumbprint
            try {
                $badConnection.Bind()
                throw "$($target.Name) bind attempt $attempt unexpectedly succeeded."
            }
            catch {
                $ldapException = $null
                if ($_.Exception -is [System.DirectoryServices.Protocols.LdapException]) {
                    $ldapException = $_.Exception
                }
                elseif ($null -ne $_.Exception.InnerException -and $_.Exception.InnerException -is [System.DirectoryServices.Protocols.LdapException]) {
                    $ldapException = $_.Exception.InnerException
                }

                if ($attempt -lt 4) {
                    Assert-True ($null -ne $ldapException -and $ldapException.ErrorCode -eq 49) "$($target.Name) bind attempt $attempt should fail with invalid credentials."
                }
                if ($attempt -eq 4) {
                    $message = if ($null -ne $ldapException) { $ldapException.ServerErrorMessage + ' ' + $ldapException.Message } else { $_.Exception.Message }
                    $fourthRateLimited = ($null -ne $ldapException -and $ldapException.ErrorCode -ne 49) -or $message -match 'busy'
                }
            }
            finally {
                $badConnection.Dispose()
            }
        }
        Assert-True $fourthRateLimited "$($target.Name) fourth bind attempt should be rate limited."
    }

    Write-Step 'Testing LDAPS TLS transport and certificate validation'
    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $tcpClient.Connect($HostName, $LdapsPort)
        $callback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $candidate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
            return $candidate.Thumbprint -eq $ExpectedThumbprint
        }
        $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $callback)
        try {
            $sslStream.AuthenticateAsClient($HostName)
            $remoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
            Assert-True ($remoteCertificate.Thumbprint -eq $ExpectedThumbprint) 'LDAPS certificate validation failed.'
        }
        finally {
            $sslStream.Dispose()
        }
    }
    finally {
        $tcpClient.Dispose()
    }

    if (Get-LdapsearchExecutable) {
        Start-Sleep -Seconds 11
        Test-LdapsearchEndpoints -CaCertPath $CaCertPath
        return
    }

    Write-Step 'Attempting LDAPS LDAP operations through System.DirectoryServices.Protocols'
    try {
        $anonymous = New-LdapTestConnection -Port $LdapsPort -UseSsl $true -AuthType ([System.DirectoryServices.Protocols.AuthType]::Anonymous) -ExpectedThumbprint $ExpectedThumbprint
        try {
            $anonymous.Bind()
            $root = Invoke-LdapSearch -Connection $anonymous -Base '' -Filter '(objectClass=*)' -Scope ([System.DirectoryServices.Protocols.SearchScope]::Base) -Attributes @('namingContexts')
            Assert-True ($root.Entries.Count -eq 1) 'LDAPS Root DSE search should return one entry.'
        }
        finally {
            $anonymous.Dispose()
        }
    }
    catch {
        Write-Warning 'System.DirectoryServices.Protocols could not execute LDAPS LDAP operations on this runtime. TLS transport and certificate validation still succeeded.'
    }
}

$state = $null
$caCertPath = $null
try {
    if (-not $SkipServerStart) {
        Write-Step 'Starting NanoLDAP for integration testing'
        $rootPath = Join-Path ([System.IO.Path]::GetTempPath()) ("nanoldap-e2e-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $rootPath
        $state = Start-NanoLDAP -RootPath $rootPath
    }

    $certificateResponse = Invoke-WebRequest -Uri "http://${HostName}:$HttpPort/ca.crt" -SkipHttpErrorCheck
    Assert-True ($certificateResponse.StatusCode -eq 200) 'Certificate endpoint was not reachable.'
    $certificateText = Get-ResponseText -Content $certificateResponse.Content
    if ($certificateText -notmatch '(?s)-----BEGIN CERTIFICATE-----(?<body>.*?)-----END CERTIFICATE-----') {
        throw 'Certificate endpoint did not return a PEM-encoded certificate.'
    }
    $pemPayload = ($Matches.body -replace '\s', '')
    $serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($pemPayload))
    $expectedThumbprint = $serverCertificate.Thumbprint
    $caCertPath = Join-Path ([System.IO.Path]::GetTempPath()) ("nanoldap-ca-" + [guid]::NewGuid().ToString('N') + '.crt')
    Set-Content -LiteralPath $caCertPath -Value $certificateText -Encoding ascii -NoNewline

    Test-WebEndpoints
    Test-LdapEndpoints -ExpectedThumbprint $expectedThumbprint -CaCertPath $caCertPath

    Write-Host 'All integration tests passed.'
}
finally {
    if ($null -ne $caCertPath -and (Test-Path -LiteralPath $caCertPath)) {
        Remove-Item -LiteralPath $caCertPath -Force
    }
    Stop-NanoLDAP -State $state
}
