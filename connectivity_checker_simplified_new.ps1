#Requires -Version 5.1
<#
.SYNOPSIS
    Entra ID & Intune Connectivity Checker - Full Endpoint Coverage
.DESCRIPTION
    Tests all Microsoft-documented endpoints required for:
    - Entra Hybrid Join (https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join)
    - Intune MDM Enrollment & Management (https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints)
    Compatible with PowerShell 5.1 and 7.x.
.PARAMETER ExportCSV
    Export connectivity test results to CSV on Desktop.
.PARAMETER ExportSummaryTable
    Export network requirements summary to CSV on Desktop.
.PARAMETER ExportHTML
    Generate a full HTML report with tabbed view (Action Required, Overview, All Endpoints, Blocked, SSL Bypass, Proxy Config, Summary).
.PARAMETER Region
    Tenant region for region-specific endpoints: Global (default), AsiaPacific.
.EXAMPLE
    .\connectivity_checker_simplified.ps1
    .\connectivity_checker_simplified.ps1 -ExportHTML
    .\connectivity_checker_simplified.ps1 -ExportCSV
    .\connectivity_checker_simplified.ps1 -Region AsiaPacific -ExportHTML
    .\connectivity_checker_simplified.ps1 -ExportCSV -ExportSummaryTable -ExportHTML
.NOTES
    Version : 2.1 | 2026-04-03
    Author  : PIWI 2026

    Description:
        Tests network connectivity to all Microsoft-documented endpoints required for
        Entra ID Hybrid Join and Intune MDM enrollment/management. Checks TCP
        reachability (port 443/80), SSL handshake validity, and reports which endpoints
        are Required vs. Optional. Flags endpoints where SSL inspection must be bypassed
        per Microsoft documentation. Supports regional endpoint selection and optional
        CSV/summary-table export.

        Key notes:
          - SSL/TLS inspection is NOT supported for: *.manage.microsoft.com,
            *.dm.microsoft.com, DHA endpoints, MAA Attestation, MS Store API,
            EPM and MDE endpoints.
          - Intune requires unauthenticated proxy access for:
            manage.microsoft.com, *.azureedge.net, graph.microsoft.com
          - Delivery Optimization also uses TCP 7680 (P2P) and UDP 3544 (Teredo).
          - Intune uses Azure Front Door (AzureFrontDoor.MicrosoftSecurity).
            IP ranges in Azure IP JSON: https://www.microsoft.com/en-us/download/details.aspx?id=56519

    References:
        [1] Hybrid Join endpoints  : https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join
        [2] Intune endpoints       : https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints
        [3] M365 network principles: https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-network-connectivity-principles
#>

[CmdletBinding()]
param(
    [switch]$ExportCSV,
    [switch]$ExportSummaryTable,
    [ValidateSet("Global", "AsiaPacific")]
    [string]$Region = "Global",
    [string]$CSVPath = "$env:USERPROFILE\Desktop\ConnectivityCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$SummaryCSVPath = "$env:USERPROFILE\Desktop\NetworkRequirements_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$ExportHTML,
    [string]$HTMLPath = "$env:USERPROFILE\Desktop\ConnectivityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
)

$ErrorActionPreference = 'SilentlyContinue'

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Store user context for reports
$RunByUser = "$env:USERDOMAIN\$env:USERNAME"

# ══════════════════════════════════════════════════════════════
#  ENDPOINT DEFINITIONS
#  Sources:
#    [1] https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join#prerequisites
#    [2] https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints
# ══════════════════════════════════════════════════════════════

$Endpoints = [System.Collections.ArrayList]::new()

# Helper to determine geographic region based on URL
function Get-EndpointRegion {
    param([string]$URL)
    
    # Region-specific patterns
    if ($URL -match "imeswda|macsidecar\.manage|intunemaape[1-6]\.(eus|cus|wus|scus|ncus)") {
        return "North America"
    }
    elseif ($URL -match "imeswdb|macsidecareu|intunemaape(7|8|9|10|11|12)\.(neu|weu)") {
        return "Europe"
    }
    elseif ($URL -match "imeswdc|macsidecarap|intunemaape(13|17|18|19)\.jpe") {
        return "Asia Pacific"
    }
    else {
        return "Global"
    }
}

# Helper to add endpoints cleanly
function Add-EP {
    param([string]$Cat, [string]$Name, [string]$URL, [int]$Port = 443, [bool]$Critical = $false, [string]$Ref = "", [string]$Note = "", [bool]$NoSSLInspection = $false, [bool]$ProxyUnauth = $false, [string]$WildcardRule = "-")
    [void]$script:Endpoints.Add([PSCustomObject]@{
            Category = $Cat; Name = $Name; URL = $URL; Port = $Port
            Critical = $Critical; Ref = $Ref; Note = $Note
            NoSSLInspection = $NoSSLInspection
            ProxyUnauth = $ProxyUnauth
            WildcardRule = $WildcardRule
            GeoRegion = Get-EndpointRegion -URL $URL
        })
}

# ══════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════
function Export-HTMLReport {
    param([string]$Path)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $hostname = $env:COMPUTERNAME
    $osVer = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { "N/A" }

    # ── Data prep ──
    $actBlocked = @($Results | Where-Object { $_.Status -in "DNS_FAIL", "TCP_BLOCKED" -and $_.DNS_Public -ne "Not publicly resolvable" })
    $actCritBlocked = @($Results | Where-Object { $_.Status -in "DNS_FAIL", "TCP_BLOCKED" -and $_.Critical -eq "YES" -and $_.DNS_Public -ne "Not publicly resolvable" })
    $actSSL = @($Results | Where-Object { $_.Action_SSL -ne "-" })
    $actSSLBlocked = @($Results | Where-Object { $_.Action_SSL -ne "-" -and $_.Status -ne "OK" })
    $actProxy = @($Results | Where-Object { $_.Action_Proxy -ne "-" })
    $actSSLInspect = @($Results | Where-Object { $_.Status -eq "TLS_FAIL" })
    $rPassCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
    $rFailCount = $actCritBlocked.Count
    $rWarnCount = ($Results | Where-Object { $_.Status -in "DNS_FAIL", "TCP_BLOCKED" -and $_.Critical -eq "no" -and $_.DNS_Public -ne "Not publicly resolvable" }).Count

    $cBlocked = if ($actCritBlocked.Count -gt 0) { "#ef5350" } elseif ($actBlocked.Count -gt 0) { "#ffa726" } else { "#2ecc71" }
    $cSSL = if ($actSSL.Count -gt 0) { "#ffa726" } else { "#2ecc71" }
    $cProxy = if ($actProxy.Count -gt 0) { "#42a5f5" } else { "#2ecc71" }
    $cInspect = if ($actSSLInspect.Count -gt 0) { "#ef5350" } else { "#2ecc71" }

    function Esc { param([string]$s); $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' }
    function Get-TagE {
        param([string]$status, [string]$crit = "no")
        $d = if ($status -eq "TCP_BLOCKED") { "BLOCKED" } else { $status }
        switch ($status) {
            "OK" { "<span class='tag t-ok'>OK</span>" }
            "TCP_BLOCKED" { if ($crit -eq "YES") { "<span class='tag t-fail'>BLOCKED</span>" } else { "<span class='tag t-warn'>BLOCKED</span>" } }
            "DNS_FAIL" { if ($crit -eq "YES") { "<span class='tag t-fail'>DNS FAIL</span>" } else { "<span class='tag t-warn'>DNS FAIL</span>" } }
            "TLS_FAIL" { "<span class='tag t-warn'>TLS FAIL</span>" }
            default { "<span class='tag t-warn'>$(Esc $d)</span>" }
        }
    }

    $h = [System.Text.StringBuilder]::new()
    [void]$h.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connectivity Report</title><style>')
    [void]$h.AppendLine('*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",sans-serif;background:#1a1a2e;color:#e0e0e0;font-size:13px}')
    [void]$h.AppendLine('.header{background:linear-gradient(135deg,#16213e,#0f3460);padding:24px 32px;border-bottom:2px solid #00b4d8}')
    [void]$h.AppendLine('.header h1{font-size:22px;color:#00b4d8;font-weight:700}.header p{color:#aaa;font-size:12px;margin-top:4px}')
    [void]$h.AppendLine('.tabs{display:flex;gap:0;background:#16213e;padding:0 32px;border-bottom:1px solid #2a2a4a;overflow-x:auto}')
    [void]$h.AppendLine('.tb{padding:10px 16px;cursor:pointer;color:#888;border:none;background:none;font-size:12px;font-weight:600;white-space:nowrap;border-top:3px solid transparent;transition:all .2s}')
    [void]$h.AppendLine('.tb:hover{color:#ccc;background:#1e2a4a}.tb.active{color:#00b4d8;border-top-color:#00b4d8;background:#1a1a2e}')
    [void]$h.AppendLine('.tb.t-red.active{color:#ef5350;border-top-color:#ef5350}.tb.t-amber.active{color:#ffa726;border-top-color:#ffa726}.tb.t-blue.active{color:#42a5f5;border-top-color:#42a5f5}')
    [void]$h.AppendLine('.tb.t-action{border-width:2px}.tb.t-action.active{color:#ffca28;border-top-color:#ffca28;font-weight:800}')
    [void]$h.AppendLine('.tc{display:none}.main{padding:24px 32px}')
    [void]$h.AppendLine('.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}')
    [void]$h.AppendLine('.card{flex:1;min-width:160px;padding:16px 20px;border-radius:8px;color:#fff}.card h3{font-size:26px;font-weight:800}.card p{font-size:11px;opacity:.85;margin-top:4px}')
    [void]$h.AppendLine('.section{background:#16213e;border-radius:8px;padding:20px;margin-bottom:20px}')
    [void]$h.AppendLine('.section h2{font-size:15px;margin-bottom:14px;color:#00b4d8;display:flex;align-items:center;gap:8px}')
    [void]$h.AppendLine('table{width:100%;border-collapse:collapse;font-size:12px}th{background:#0f3460;color:#00b4d8;text-align:left;padding:8px 10px;position:sticky;top:0}')
    [void]$h.AppendLine('td{padding:7px 10px;border-bottom:1px solid #1e2a4a}tr:hover td{background:#1e2a4a}')
    [void]$h.AppendLine('.tbl-wrap{overflow-x:auto;border-radius:6px;border:1px solid #2a2a4a}')
    [void]$h.AppendLine('.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}')
    [void]$h.AppendLine('.t-ok{background:#1b4332;color:#2ecc71}.t-fail{background:#4a1515;color:#ef5350}.t-warn{background:#4a3000;color:#ffa726}.t-ssl{background:#1a2a4a;color:#42a5f5}.t-proxy{background:#1a3a2a;color:#2ecc71}')
    [void]$h.AppendLine('.alert{padding:12px 16px;border-radius:6px;margin-bottom:12px;font-size:12px;border-left:4px solid}')
    [void]$h.AppendLine('.alert-warn{background:#2a1f00;border-color:#ffa726;color:#ffd180}.alert-info{background:#001a2a;border-color:#42a5f5;color:#90caf9}.alert-danger{background:#2a0000;border-color:#ef5350;color:#ff8a80}')
    [void]$h.AppendLine('.step{background:#12192b;border-radius:8px;padding:16px 20px;margin-bottom:14px;border-left:4px solid}')
    [void]$h.AppendLine('.step-red{border-color:#ef5350}.step-amber{border-color:#ffa726}.step-blue{border-color:#42a5f5}')
    [void]$h.AppendLine('.step h3{font-size:13px;font-weight:700;margin-bottom:10px}')
    [void]$h.AppendLine('.step-red h3{color:#ef5350}.step-amber h3{color:#ffa726}.step-blue h3{color:#42a5f5}')
    [void]$h.AppendLine('textarea{width:100%;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;resize:vertical;margin-top:8px}')
    [void]$h.AppendLine('.ta-red{border-color:#ef5350!important}.ta-amber{border-color:#ffa726!important}.ta-blue{border-color:#42a5f5!important}')
    [void]$h.AppendLine('.copy-label{font-size:11px;color:#aaa;margin-top:14px;margin-bottom:4px}')
    [void]$h.AppendLine('.legend-box{background:#12192b;border:1px solid #2a2a4a;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:11px;color:#aaa;line-height:1.8}')
    [void]$h.AppendLine('.legend-box strong{color:#ccc}.legend-box span{margin-right:14px}')
    [void]$h.AppendLine('</style></head><body>')

    [void]$h.AppendLine('<div class="header"><h1>&#9889; Entra ID &amp; Intune Connectivity Report</h1>')
    [void]$h.AppendLine("<p>Generated: $ts &nbsp;|&nbsp; Host: $(Esc $hostname) &nbsp;|&nbsp; User: $(Esc $RunByUser) &nbsp;|&nbsp; Region: $(Esc $Region)</p></div>")

    # ── Network Context Bar ──
    $ctxItems = [System.Collections.ArrayList]::new()
    [void]$ctxItems.Add("&#128225; DNS: <strong>$(Esc $NetworkCtx.DNSServers)</strong>$(if ($NetworkCtx.CorporateDNSLikely) { ' <span style=''color:#ffa726''> ⚠️ corporate/private range</span>' } else { '' })")
    [void]$ctxItems.Add("VPN: <strong>$(if ($NetworkCtx.VPNDetected) { "<span style='color:#ffa726'>⚠️ DETECTED — $(Esc $NetworkCtx.VPNAdapter)</span>" } else { 'Not detected' })</strong>")
    [void]$ctxItems.Add("Proxy (IE): <strong>$(if ($NetworkCtx.ProxyEnabled) { "<span style='color:#ffa726'>⚠️ $(Esc $NetworkCtx.ProxyServer)</span>" } else { 'None' })</strong>$(if ($NetworkCtx.WPADEnabled) { ' <span style=''color:#ffa726''>[WPAD on]</span>' } else { '' })")
    [void]$ctxItems.Add("Proxy (WinHTTP): <strong>$(if ($NetworkCtx.WinHTTPProxy -ne '-') { "<span style='color:#ffa726'>⚠️ $(Esc $NetworkCtx.WinHTTPProxy)</span>" } else { 'None' })</strong>")
    $ctxBg = if ($NetworkCtx.CorporateDNSLikely -or $NetworkCtx.VPNDetected -or $NetworkCtx.ProxyEnabled -or $NetworkCtx.WinHTTPProxy -ne "-") { "#1a1a0a;border-left:4px solid #ffa726" } else { "#0f1a0f;border-left:4px solid #2ecc71" }
    [void]$h.AppendLine("<div style='background:$ctxBg;padding:8px 16px;font-size:12px;color:#bbb;display:flex;gap:24px;flex-wrap:wrap;align-items:center'>")
    [void]$h.AppendLine("<span style='color:#888;font-weight:700;margin-right:4px'>&#127758; NETWORK CONTEXT:</span>")
    foreach ($item in $ctxItems) { [void]$h.AppendLine("<span>$item</span>") }
    [void]$h.AppendLine("</div>")

    # ── Tab nav ──
    $nAll = $Results.Count
    $nBlocked = $actBlocked.Count
    $nSSL = $actSSL.Count
    $nProxy = $actProxy.Count
    $tabActClass = if ($actCritBlocked.Count -gt 0) { 't-red t-action' } elseif ($actBlocked.Count -gt 0) { 't-amber t-action' } else { 't-action' }

    [void]$h.AppendLine("<div class='tabs'>")
    [void]$h.AppendLine("<button class='tb $tabActClass active' onclick='showTab(""tab-action"",this)'>&#9889; Action Required</button>")
    [void]$h.AppendLine("<button class='tb' onclick='showTab(""tab-overview"",this)'>&#128202; Overview</button>")
    [void]$h.AppendLine("<button class='tb' onclick='showTab(""tab-all"",this)'>&#128269; All Endpoints ($nAll)</button>")
    [void]$h.AppendLine("<button class='tb t-red' onclick='showTab(""tab-blocked"",this)'>&#128308; Blocked ($nBlocked)</button>")
    [void]$h.AppendLine("<button class='tb t-amber' onclick='showTab(""tab-ssl"",this)'>&#128293; SSL Bypass ($nSSL)</button>")
    [void]$h.AppendLine("<button class='tb t-blue' onclick='showTab(""tab-proxy"",this)'>&#127760; Proxy Config ($nProxy)</button>")
    [void]$h.AppendLine("<button class='tb' onclick='showTab(""tab-summary"",this)'>&#128187; Summary</button>")
    [void]$h.AppendLine("</div>")

    [void]$h.AppendLine("<div class='main'>")

    # ════════════════════════════════════════════
    # TAB: ACTION REQUIRED (default open)
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-action' class='tc' style='display:block'>")

    # Summary cards
    [void]$h.AppendLine("<div class='cards'>")
    [void]$h.AppendLine("<div class='card' style='background:$cBlocked'><h3>$($actCritBlocked.Count)</h3><p>Critical Blocked</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:$cSSL'><h3>$($actSSL.Count)</h3><p>Verify SSL Bypass (MS docs)</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:$cProxy'><h3>$($actProxy.Count)</h3><p>Verify Unauthenticated Proxy (MS docs)</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:$cInspect'><h3>$($actSSLInspect.Count)</h3><p>SSL Inspected Now</p></div>")
    [void]$h.AppendLine("</div>")

    # Legend
    [void]$h.AppendLine("<div class='legend-box'>")
    [void]$h.AppendLine("<strong>&#8505; How to read this report:</strong><br>")
    [void]$h.AppendLine("<span><span class='tag t-ok'>OK</span> &nbsp;Endpoint is reachable &mdash; but may still require configuration (see Steps 2 &amp; 3)</span><br>")
    [void]$h.AppendLine("<span><span class='tag t-fail'>BLOCKED</span> &nbsp;TCP connection refused or timed out &mdash; must be unblocked in firewall/proxy</span><br>")
    [void]$h.AppendLine("<span><span class='tag t-warn'>DNS FAIL</span> &nbsp;Hostname does not resolve &mdash; check DNS or split-DNS configuration</span><br>")
    [void]$h.AppendLine("<span><span class='tag t-warn'>TLS FAIL</span> &nbsp;TLS handshake failed &mdash; SSL inspection is likely intercepting this endpoint right now</span><br>")
    [void]$h.AppendLine("<span><span class='tag t-ssl'>BYPASS REQUIRED</span> &nbsp;Microsoft requires SSL/TLS inspection bypass for this endpoint &mdash; verify this exemption is configured in your firewall / proxy policy (required even when connection shows OK)</span><br>")
    [void]$h.AppendLine("<span><span class='tag t-proxy'>UNAUTHENTICATED PROXY</span> &nbsp;Microsoft requires unauthenticated proxy access &mdash; verify your proxy allows bypass / unauthenticated access for this endpoint. Intune runs as SYSTEM account and cannot authenticate to a proxy.</span>")
    [void]$h.AppendLine("</div>")

    # Step 1: Blocked
    [void]$h.AppendLine("<div class='step step-red'>")
    [void]$h.AppendLine("<h3>&#128308; Step 1 &mdash; Unblock these endpoints in your firewall / proxy ($($actBlocked.Count) endpoints)</h3>")
    if ($actBlocked.Count -eq 0) {
        [void]$h.AppendLine("<p style='color:#2ecc71'>&#10003; No blocked endpoints detected.</p>")
    }
    else {
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Status</th><th>Critical</th></tr>")
        foreach ($r in $actBlocked) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td>$(if($r.Critical -eq 'YES'){"<span class='tag t-fail'>CRITICAL</span>"}else{"<span class='tag t-warn'>WARN</span>"})</td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
        $blockedTxt = ($actBlocked | ForEach-Object { $_.Endpoint }) -join "&#10;"
        [void]$h.AppendLine("<p class='copy-label'>&#128203; Copy-ready list &mdash; paste into firewall / proxy team ticket:</p>")
        [void]$h.AppendLine("<textarea class='ta-red' rows='4' readonly>$blockedTxt</textarea>")
    }
    [void]$h.AppendLine("</div>")

    # Step 2: SSL bypass
    [void]$h.AppendLine("<div class='step step-amber'>")
    [void]$h.AppendLine("<h3>&#128293; Step 2 &mdash; Configure SSL/TLS inspection bypass for these endpoints ($($actSSL.Count) endpoints)</h3>")
    [void]$h.AppendLine("<div class='alert alert-warn'>&#9888; Microsoft requires SSL/TLS inspection to be <strong>disabled</strong> for these endpoints. Even when reachable, SSL inspection causes authentication failures.</div>")
    if ($actSSL.Count -eq 0) {
        [void]$h.AppendLine("<p style='color:#2ecc71'>&#10003; No SSL bypass requirements detected.</p>")
    }
    else {
        if ($actSSLInspect.Count -gt 0) {
            [void]$h.AppendLine("<div class='alert alert-danger'>&#128293; TLS handshake failures detected &mdash; active SSL inspection is likely intercepting traffic right now.</div>")
        }
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Connection Test</th><th>Action Required</th></tr>")
        foreach ($r in $actSSL) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td><span class='tag t-ssl'>BYPASS REQUIRED</span></td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
        [void]$h.AppendLine("<div class='alert alert-info' style='margin-top:10px'>&#128204; Also add wildcards: <strong>*.manage.microsoft.com &nbsp; *.dm.microsoft.com &nbsp; *.attest.azure.net</strong></div>")
        $sslTxt = ($actSSL | ForEach-Object { ($_.Endpoint -split ':')[0] }) -join "&#10;"
        [void]$h.AppendLine("<p class='copy-label'>&#128203; Copy-ready list &mdash; paste into SSL/TLS bypass policy:</p>")
        [void]$h.AppendLine("<textarea class='ta-amber' rows='4' readonly>$sslTxt</textarea>")
    }
    [void]$h.AppendLine("</div>")

    # Step 3: Proxy
    [void]$h.AppendLine("<div class='step step-blue'>")
    [void]$h.AppendLine("<h3>&#127760; Step 3 &mdash; Allow unauthenticated proxy access — SYSTEM account ($($actProxy.Count) endpoints)</h3>")
    [void]$h.AppendLine("<div class='alert alert-info'>&#8505; Intune runs under the SYSTEM account during enrollment &amp; management. Proxy authentication is not supported &mdash; these endpoints must be reachable without credentials.</div>")
    if ($actProxy.Count -eq 0) {
        [void]$h.AppendLine("<p style='color:#2ecc71'>&#10003; No unauthenticated proxy requirements detected.</p>")
    }
    else {
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Connection Test</th><th>Action Required</th></tr>")
        foreach ($r in $actProxy) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td><span class='tag t-proxy'>UNAUTHENTICATED PROXY</span></td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
        [void]$h.AppendLine("<div class='alert alert-info' style='margin-top:10px'>&#128204; Also configure bypass for wildcard: <strong>*.azureedge.net</strong> (Azure CDN &mdash; not directly testable but required by Intune)</div>")
        $proxyTxt = ($actProxy | ForEach-Object { ($_.Endpoint -split ':')[0] }) -join "&#10;"
        [void]$h.AppendLine("<p class='copy-label'>&#128203; Copy-ready list &mdash; paste into proxy exception / bypass policy:</p>")
        [void]$h.AppendLine("<textarea class='ta-blue' rows='3' readonly>$proxyTxt</textarea>")
    }
    [void]$h.AppendLine("</div>")

    [void]$h.AppendLine("</div>") # end tab-action

    # ════════════════════════════════════════════
    # TAB: OVERVIEW
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-overview' class='tc'>")
    [void]$h.AppendLine("<div class='cards'>")
    $cPass = if ($rPassCount -eq $Results.Count) { "#2ecc71" } else { "#ffa726" }
    [void]$h.AppendLine("<div class='card' style='background:$cPass'><h3>$rPassCount</h3><p>Passed</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:$cBlocked'><h3>$rFailCount</h3><p>Critical Failed</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:$(if($rWarnCount -gt 0){"#ffa726"}else{"#2ecc71"})'><h3>$rWarnCount</h3><p>Warnings</p></div>")
    [void]$h.AppendLine("<div class='card' style='background:#42a5f5'><h3>$($Results.Count)</h3><p>Total Tested</p></div>")
    [void]$h.AppendLine("</div>")
    [void]$h.AppendLine("<div class='section'><h2>&#128202; Results by Category</h2>")
    [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Total</th></tr>")
    foreach ($cat in ($Results | Select-Object -ExpandProperty Category -Unique)) {
        $catR = $Results | Where-Object { $_.Category -eq $cat }
        $cp = ($catR | Where-Object { $_.Status -eq "OK" }).Count
        $cf = ($catR | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" }).Count
        $cw = ($catR | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "no" }).Count
        [void]$h.AppendLine("<tr><td>$(Esc $cat)</td><td style='color:#2ecc71'>$cp</td><td style='color:#ef5350'>$cf</td><td style='color:#ffa726'>$cw</td><td>$($catR.Count)</td></tr>")
    }
    [void]$h.AppendLine("</table></div></div>")
    [void]$h.AppendLine("</div>") # end tab-overview

    # ════════════════════════════════════════════
    # TAB: ALL ENDPOINTS
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-all' class='tc'>")
    [void]$h.AppendLine("<div class='section'><h2>&#128269; All Endpoints ($($Results.Count))</h2>")
    [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Status</th><th>DNS</th><th>DNS_Public</th><th>TCP</th><th>TLS</th><th>OS_TLS (SCHANNEL)</th><th>DotNet_TLS_Powershell</th><th>Critical</th><th>Action: SSL Bypass (MS docs)</th><th>Action: Proxy Unauthenticated (MS docs)</th></tr>")
    foreach ($r in $Results) {
        $noSSLTag = if ($r.Action_SSL -ne "-") { "<span class='tag t-ssl'>REQUIRED</span>" } else { "" }
        $proxyTag = if ($r.Action_Proxy -ne "-") { "<span class='tag t-proxy'>REQUIRED</span>" } else { "" }
        $critTag = if ($r.Critical -eq "YES") { "<span class='tag t-fail'>YES</span>" } else { "" }
        $tlsStyle = if ($r.TLS -match "CHANGE NEEDED|upgrade") { "color:#e74c3c" } else { "" }
        $osTlsStyle = if ($r.OS_TLS -match "1\.0: ON|1\.1: ON") { "color:#e74c3c;font-size:10px" } else { "font-size:10px" }
        [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td>$(Esc $r.DNS_IP)</td><td>$(Esc $r.DNS_Public)</td><td>$(Esc $r.TCP)</td><td style='$tlsStyle'>$(Esc $r.TLS)</td><td style='$osTlsStyle'>$(Esc $r.OS_TLS)</td><td style='font-size:10px'>$(Esc $r.DotNet_TLS_Powershell)</td><td>$critTag</td><td>$noSSLTag</td><td>$proxyTag</td></tr>")
    }
    [void]$h.AppendLine("</table></div></div>")
    [void]$h.AppendLine("</div>") # end tab-all

    # ════════════════════════════════════════════
    # TAB: BLOCKED
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-blocked' class='tc'>")
    [void]$h.AppendLine("<div class='section'><h2>&#128308; Blocked / Failed Endpoints</h2>")
    if ($actBlocked.Count -eq 0) {
        [void]$h.AppendLine("<div class='alert alert-info'>&#10003; All endpoints are reachable.</div>")
    }
    else {
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Status</th><th>Critical</th><th>Note</th></tr>")
        foreach ($r in $actBlocked) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td>$(if($r.Critical -eq 'YES'){"<span class='tag t-fail'>CRITICAL</span>"}else{"<span class='tag t-warn'>OPTIONAL</span>"})</td><td>$(Esc $r.Note)</td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
    }
    [void]$h.AppendLine("</div>")
    [void]$h.AppendLine("</div>") # end tab-blocked

    # ════════════════════════════════════════════
    # TAB: SSL/TLS BYPASS
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-ssl' class='tc'>")
    [void]$h.AppendLine("<div class='section'><h2>&#128293; SSL/TLS Inspection Bypass Requirements</h2>")
    [void]$h.AppendLine("<div class='alert alert-warn'>&#9888; These endpoints must be excluded from SSL/TLS inspection. Microsoft documentation states that SSL break-and-inspect causes device management failures even when endpoints are reachable.</div>")
    if ($actSSL.Count -eq 0) {
        [void]$h.AppendLine("<div class='alert alert-info'>&#10003; No SSL bypass endpoints flagged.</div>")
    }
    else {
        if ($actSSLInspect.Count -gt 0) {
            [void]$h.AppendLine("<div class='alert alert-danger'>&#128293; TLS handshake failures detected &mdash; active SSL inspection is likely intercepting traffic right now.</div>")
        }
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Connection Test</th><th>Action Required</th><th>Critical</th><th>Note</th></tr>")
        foreach ($r in $actSSL) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td><span class='tag t-ssl'>BYPASS REQUIRED</span></td><td>$(if($r.Critical -eq 'YES'){"<span class='tag t-fail'>CRITICAL</span>"}else{"<span class='tag t-warn'>OPTIONAL</span>"})</td><td>$(Esc $r.Note)</td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
        [void]$h.AppendLine("<div class='alert alert-info' style='margin-top:14px'>&#128204; Recommended wildcard SSL bypass rules:<br><strong>*.manage.microsoft.com &nbsp;&nbsp; *.dm.microsoft.com &nbsp;&nbsp; *.attest.azure.net &nbsp;&nbsp; has.spserv.microsoft.com</strong></div>")
    }
    [void]$h.AppendLine("</div>")
    [void]$h.AppendLine("</div>") # end tab-ssl

    # ════════════════════════════════════════════
    # TAB: PROXY CONFIG
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-proxy' class='tc'>")
    [void]$h.AppendLine("<div class='section'><h2>&#127760; Unauthenticated Proxy Access Requirements</h2>")
    [void]$h.AppendLine("<div class='alert alert-info'>&#8505; Intune device management runs under the SYSTEM account. Proxy servers that require authentication will block enrollment and management. Configure proxy bypass or anonymous access for these endpoints.</div>")
    if ($actProxy.Count -eq 0) {
        [void]$h.AppendLine("<div class='alert alert-info'>&#10003; No unauthenticated proxy requirements detected.</div>")
    }
    else {
        [void]$h.AppendLine("<div class='tbl-wrap'><table><tr><th>Category</th><th>Name</th><th>Endpoint</th><th>Connection Test</th><th>Action Required</th><th>Note</th></tr>")
        foreach ($r in $actProxy) {
            [void]$h.AppendLine("<tr><td>$(Esc $r.Category)</td><td>$(Esc $r.Name)</td><td><code>$(Esc $r.Endpoint)</code></td><td>$(Get-TagE $r.Status $r.Critical)</td><td><span class='tag t-proxy'>UNAUTHENTICATED PROXY</span></td><td>$(Esc $r.Note)</td></tr>")
        }
        [void]$h.AppendLine("</table></div>")
        [void]$h.AppendLine("<div class='alert alert-info' style='margin-top:14px'>&#128204; Also configure bypass for wildcard: <strong>*.azureedge.net</strong> (Azure CDN &mdash; not directly testable but required by Intune)</div>")
    }
    [void]$h.AppendLine("</div>")
    [void]$h.AppendLine("</div>") # end tab-proxy

    # ════════════════════════════════════════════
    # TAB: SUMMARY
    # ════════════════════════════════════════════
    [void]$h.AppendLine("<div id='tab-summary' class='tc'>")
    [void]$h.AppendLine("<div class='section'><h2>&#128187; Script &amp; System Information</h2>")
    [void]$h.AppendLine("<div class='tbl-wrap'><table>")
    [void]$h.AppendLine("<tr><td><strong>Report Generated</strong></td><td>$ts</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Run By</strong></td><td>$(Esc $RunByUser)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Computer Name</strong></td><td>$(Esc $hostname)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>OS Version</strong></td><td>$(Esc $osVer)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Running as Admin</strong></td><td>$(if($IsAdmin){'Yes'}else{'No'})</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Region</strong></td><td>$(Esc $Region)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Total Endpoints Tested</strong></td><td>$($Results.Count)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Passed</strong></td><td>$rPassCount</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Critical Failures</strong></td><td>$rFailCount</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Warnings</strong></td><td>$rWarnCount</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>SSL Bypass Required (MS docs)</strong></td><td>$($actSSL.Count)</td></tr>")
    [void]$h.AppendLine("<tr><td><strong>Proxy Unauthenticated Required (MS docs)</strong></td><td>$($actProxy.Count)</td></tr>")
    [void]$h.AppendLine("</table></div></div>")
    [void]$h.AppendLine("</div>") # end tab-summary

    [void]$h.AppendLine("</div>") # end main

    [void]$h.AppendLine("<script>")
    [void]$h.AppendLine("function showTab(id,btn){document.querySelectorAll('.tc').forEach(t=>t.style.display='none');document.querySelectorAll('.tb').forEach(b=>b.classList.remove('active'));document.getElementById(id).style.display='block';btn.classList.add('active');}")
    [void]$h.AppendLine("</script></body></html>")

    $h.ToString() | Out-File -FilePath $Path -Encoding UTF8 -Force
    Write-Host "  HTML report exported: $Path" -ForegroundColor Green
}

# ── ENTRA ID / HYBRID JOIN [Ref 1] ──────────────────────────
Add-EP "Entra ID - Hybrid Join"  "Login / Authentication"                "login.microsoftonline.com"              443 $true  "[1] Required" "" $true
Add-EP "Entra ID - Hybrid Join"  "Login (Microsoft)"                     "login.microsoft.com"                    443 $true  "[MS] Required" "" $true
Add-EP "Entra ID - Hybrid Join"  "Device Registration"                   "enterpriseregistration.windows.net"     443 $true  "[1] Required" "" $true
Add-EP "Entra ID - Hybrid Join"  "Device Registration (Microsoft)"       "enterpriseregistration.microsoft.com"   443 $true  "[MS] Required" "" $true
Add-EP "Entra ID - Hybrid Join"  "Device Registration (cert auth)"       "certauth.enterpriseregistration.windows.net" 443 $true "[2] ID:59" "" $true
Add-EP "Entra ID - Hybrid Join"  "Device Login"                          "device.login.microsoftonline.com"       443 $true  "[1] Required" "Exclude from TLS break-and-inspect" $true
Add-EP "Entra ID - Hybrid Join"  "Seamless SSO / Autologon"              "autologon.microsoftazuread-sso.com"     443 $false "[1] If using SSO"

# ── ENTRA ID / AUTHENTICATION [Ref 2 ID:56] ─────────────────
Add-EP "Entra ID - Auth"         "Login (HTTP redirect)"                 "login.microsoftonline.com"               80 $false "[2] ID:56" "" $true
Add-EP "Entra ID - Auth"         "Login (legacy)"                        "login.windows.net"                      443 $false "[2] ID:56"
Add-EP "Entra ID - Auth"         "Graph API"                             "graph.microsoft.com"                    443 $true  "[2] ID:56" "Requires unauthenticated proxy access" $false $true
Add-EP "Entra ID - Auth"         "Graph API (legacy)"                    "graph.windows.net"                      443 $true  "[2] ID:56"
Add-EP "Entra ID - Auth"         "Azure DRS"                             "drs.windows.net"                        443 $true  "[1][2]"
Add-EP "Entra ID - Auth"         "STS / Token Service"                   "sts.windows.net"                        443 $true  "[1][2]"
Add-EP "Entra ID - Auth"         "STS / Token Service (MSFT)"            "msft.sts.microsoft.com"                 443 $true  "[MS] Required" "Certificate enrollment" $true
Add-EP "Entra ID - Auth"         "Auth CDN (msftauth)"                   "aadcdn.msftauth.net"                    443 $true  "[2] ID:181" "" $true
Add-EP "Entra ID - Auth"         "Auth CDN (msauth)"                     "aadcdn.msauth.net"                      443 $true  "[2] ID:181" "" $true
Add-EP "Entra ID - Auth"         "Auth CDN (alcdn)"                      "alcdn.msauth.net"                       443 $true  "[2] ID:181"
Add-EP "Entra ID - Auth"         "MS Account (Live)"                     "account.live.com"                       443 $true  "[2] ID:97"
Add-EP "Entra ID - Auth"         "MS Account Login (Live)"               "login.live.com"                         443 $true  "[2] ID:97"

# ── INTUNE CORE SERVICE [Ref 2 ID:163] ──────────────────────
Add-EP "Intune - Core"           "MDM Enrollment"                        "enrollment.manage.microsoft.com"        443 $true  "[2] ID:163" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Enterprise Enrollment"                 "enterpriseenrollment.manage.microsoft.com"   443 $true  "[2] ID:163" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Enterprise Enrollment (-s alt)"        "enterpriseenrollment-s.manage.microsoft.com" 443 $true  "[2] ID:163" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Management Service"                    "manage.microsoft.com"                   443 $true  "[2] ID:163" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Device Management (DM)"                "dm.microsoft.com"                       443 $true  "[2] MDE/EPM" "Bare wildcard domain (*.dm.microsoft.com) — DNS Resolution Failed (Endpoint may not be a standalone host). SSL inspection NOT supported (MDM, EPM, MDE)." $true $false "*.dm.microsoft.com"
Add-EP "Intune - Core"           "Portal"                                "portal.manage.microsoft.com"            443 $false "[2] ID:163" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Compliance"                            "compliance.manage.microsoft.com"        443 $false "[2]" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Diagnostics"                           "diagnostics.manage.microsoft.com"       443 $false "[2]" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Config Service"                        "config.manage.microsoft.com"            443 $false "[2]" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true
Add-EP "Intune - Core"           "Fef Service (sample NA)"               "fef.msuc06.manage.microsoft.com"        443 $false "[2]" "SSL inspection NOT supported | Unauthenticated proxy access required" $true $true

# ── INTUNE - WIN32 APPS CDN [Ref 2 ID:170] ──────────────────
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swda01)"                    "swda01-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swda02)"                    "swda02-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdb01)"                    "swdb01-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdb02)"                    "swdb02-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdc01)"                    "swdc01-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdc02)"                    "swdc02-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdd01)"                    "swdd01-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdd02)"                    "swdd02-mscdn.manage.microsoft.com"      443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdin01)"                   "swdin01-mscdn.manage.microsoft.com"     443 $true  "[2] ID:170"
Add-EP "Intune - Win32 Apps"     "Win32 CDN (swdin02)"                   "swdin02-mscdn.manage.microsoft.com"     443 $true  "[2] ID:170"

# ── INTUNE - SCRIPTS & IME CDN (Region-specific) [Ref 2] ────
$imeCDN = switch ($Region) {
    "Global" {
        @(
            @{ N = "IME CDN Primary (NA)"; U = "imeswda-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (NA)"; U = "imeswda-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (NA)"; U = "imeswda-afd-hotfix.manage.microsoft.com" }
            @{ N = "IME CDN Primary (EU)"; U = "imeswdb-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (EU)"; U = "imeswdb-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (EU)"; U = "imeswdb-afd-hotfix.manage.microsoft.com" }
        )
    }
    "AsiaPacific" {
        @(
            @{ N = "IME CDN Primary (AP)"; U = "imeswdc-afd-primary.manage.microsoft.com" }
            @{ N = "IME CDN Secondary (AP)"; U = "imeswdc-afd-secondary.manage.microsoft.com" }
            @{ N = "IME CDN Hotfix (AP)"; U = "imeswdc-afd-hotfix.manage.microsoft.com" }
        )
    }
}
foreach ($cdn in $imeCDN) {
    Add-EP "Intune - Scripts/IME" $cdn.N $cdn.U 443 $true "[2] Scripts/Win32"
}

# ── INTUNE - DELIVERY OPTIMIZATION [Ref 2 ID:172] ───────────
Add-EP "Intune - Delivery Opt"   "DO Discovery"                          "do.dsp.mp.microsoft.com"                443 $true  "[2] ID:172" "Bare wildcard domain (*.do.dsp.mp.microsoft.com) — DNS Resolution Failed (Endpoint may not be a standalone host). Also allow port 80; P2P: TCP 7680 + UDP 3544 (Teredo)." $false $false "*.do.dsp.mp.microsoft.com"
Add-EP "Intune - Delivery Opt"   "DO Download"                           "dl.delivery.mp.microsoft.com"           443 $true  "[2] ID:172" "Bare wildcard domain (*.dl.delivery.mp.microsoft.com) — DNS Resolution Failed (Endpoint may not be a standalone host). Also allow port 80; P2P: TCP 7680 + UDP 3544 (Teredo)." $false $false "*.dl.delivery.mp.microsoft.com"

# ── INTUNE - FEATURE DEPLOYMENT [Ref 2 ID:189,190,192] ──────
Add-EP "Intune - Dependencies"   "Feature Config (Edge/Skype)"           "config.edge.skype.com"                  443 $true  "[2] ID:189"
Add-EP "Intune - Dependencies"   "Feature Config (ECS)"                  "ecs.office.com"                         443 $true  "[2] ID:189"
Add-EP "Intune - Dependencies"   "Endpoint Discovery"                    "go.microsoft.com"                       443 $true  "[2] ID:190"
Add-EP "Intune - Dependencies"   "Organizational Messages"               "fd.api.orgmsg.microsoft.com"            443 $true  "[2] ID:192"
Add-EP "Intune - Dependencies"   "Org Messages Personalization"          "ris.prod.api.personalization.ideas.microsoft.com" 443 $true  "[2] ID:192"

# ── INTUNE - AZURE ATTESTATION (Region-specific) [Ref 2] ────
$attestation = switch ($Region) {
    "Global" {
        @(
            @{ N = "Attestation (EUS)"; U = "intunemaape1.eus.attest.azure.net" }
            @{ N = "Attestation (EUS2)"; U = "intunemaape2.eus2.attest.azure.net" }
            @{ N = "Attestation (CUS)"; U = "intunemaape3.cus.attest.azure.net" }
            @{ N = "Attestation (WUS)"; U = "intunemaape4.wus.attest.azure.net" }
            @{ N = "Attestation (SCUS)"; U = "intunemaape5.scus.attest.azure.net" }
            @{ N = "Attestation (NCUS)"; U = "intunemaape6.ncus.attest.azure.net" }
            @{ N = "Attestation (NEU1)"; U = "intunemaape7.neu.attest.azure.net" }
            @{ N = "Attestation (NEU2)"; U = "intunemaape8.neu.attest.azure.net" }
            @{ N = "Attestation (NEU3)"; U = "intunemaape9.neu.attest.azure.net" }
            @{ N = "Attestation (WEU1)"; U = "intunemaape10.weu.attest.azure.net" }
            @{ N = "Attestation (WEU2)"; U = "intunemaape11.weu.attest.azure.net" }
            @{ N = "Attestation (WEU3)"; U = "intunemaape12.weu.attest.azure.net" }
        )
    }
    "AsiaPacific" {
        @(
            @{ N = "Attestation (JPE1)"; U = "intunemaape13.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE2)"; U = "intunemaape17.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE3)"; U = "intunemaape18.jpe.attest.azure.net" }
            @{ N = "Attestation (JPE4)"; U = "intunemaape19.jpe.attest.azure.net" }
        )
    }
}
foreach ($att in $attestation) {
    Add-EP "Intune - Attestation" $att.N $att.U 443 $true "[2] DHA/MAA" "SSL inspection NOT supported" $true
}

# ── INTUNE - MACOS CDN (Region-specific) [Ref 2] ────────────
$macCDN = switch ($Region) {
    "Global" {
        @(
            @{ N = "macOS Sidecar CDN (NA)"; U = "macsidecar.manage.microsoft.com" }
            @{ N = "macOS Sidecar CDN (EU)"; U = "macsidecareu.manage.microsoft.com" }
        )
    }
    "AsiaPacific" { @( @{ N = "macOS Sidecar CDN (AP)"; U = "macsidecarap.manage.microsoft.com" } ) }
}
foreach ($mac in $macCDN) {
    Add-EP "Intune - macOS" $mac.N $mac.U 443 $true "[2] macOS Apps/Scripts"
}

# ── WINDOWS PUSH NOTIFICATIONS [Ref 2 ID:171] ───────────────
Add-EP "Windows - WNS"          "WNS (wns.windows.com)"                 "wns.windows.com"                        443 $true  "[2] ID:171" "Bare wildcard domain (*.wns.windows.com) — DNS Resolution Failed (Endpoint may not be a standalone host)." $false $false "*.wns.windows.com"
Add-EP "Windows - WNS"          "WNS (notify.windows.com)"              "notify.windows.com"                     443 $true  "[2] ID:171" "Bare wildcard domain (*.notify.windows.com) — DNS Resolution Failed (Endpoint may not be a standalone host)." $false $false "*.notify.windows.com"
Add-EP "Windows - WNS"          "WNS (sin.notify)"                      "sin.notify.windows.com"                 443 $true  "[2] ID:171"
Add-EP "Windows - WNS"          "WNS (sinwns1011421)"                   "sinwns1011421.wns.windows.com"          443 $true  "[2] ID:171"

# ── WINDOWS AUTOPILOT [Ref 2 ID:164,165,169,173] ────────────
Add-EP "Windows - Autopilot"    "Passport Client Config"                "clientconfig.passport.net"               443 $true  "[2] ID:169"
Add-EP "Windows - Autopilot"    "Windows Phone"                         "windowsphone.com"                       443 $true  "[2] ID:169"
Add-EP "Windows - Autopilot"    "S-Microsoft CDN"                       "c.s-microsoft.com"                      443 $true  "[2] ID:169"
Add-EP "Windows - Autopilot"    "TPM Attestation (Intel)"               "ekop.intel.com"                         443 $true  "[2] ID:173"
Add-EP "Windows - Autopilot"    "TPM Attestation (Microsoft)"           "ekcert.spserv.microsoft.com"            443 $true  "[2] ID:173"
Add-EP "Windows - Autopilot"    "TPM Attestation (AMD)"                 "ftpm.amd.com"                           443 $true  "[2] ID:173"
Add-EP "Windows - Autopilot"    "Autopilot Diag Upload (EU)"            "lgmsapeweu.blob.core.windows.net"       443 $true  "[2] ID:182"
Add-EP "Windows - Autopilot"    "Autopilot Diag Upload (NA)"            "lgmsapewus2.blob.core.windows.net"      443 $true  "[2] ID:182"
Add-EP "Windows - Autopilot"    "Autopilot Diag Upload (SEA)"           "lgmsapesea.blob.core.windows.net"       443 $true  "[2] ID:182"
Add-EP "Windows - Autopilot"    "Autopilot Diag Upload (AUS)"           "lgmsapeaus.blob.core.windows.net"       443 $true  "[2] ID:182"
Add-EP "Windows - Autopilot"    "Autopilot Diag Upload (IND)"           "lgmsapeind.blob.core.windows.net"       443 $true  "[2] ID:182"

# ── WINDOWS OS SERVICES ─────────────────────────────────────
Add-EP "Windows - OS"           "Windows Update"                         "update.microsoft.com"                   443 $true  "[2] ID:164"
Add-EP "Windows - OS"           "Windows Update (windowsupdate)"         "windowsupdate.com"                      80  $true  "[2] ID:164" "Bare wildcard domain (*.windowsupdate.com) — DNS Resolution Failed (Endpoint may not be a standalone host). Also allow port 443." $false $false "*.windowsupdate.com"
Add-EP "Windows - OS"           "Windows Update (download)"              "download.microsoft.com"                 443 $true  "[2] ID:164"
Add-EP "Windows - OS"           "Autopilot Download (adl)"               "adl.windows.com"                        443 $true  "[2] ID:164"
Add-EP "Windows - OS"           "Traffic Shaping (DO)"                   "tsfe.trafficshaping.dsp.mp.microsoft.com" 443 $true  "[2] ID:164"
Add-EP "Windows - OS"           "NTP Time Sync"                          "time.windows.com"                       123 $false "[2] ID:165" "NTP uses UDP 123; this TCP check on port 123 may show TCP_BLOCKED — that is expected for NTP. Verify UDP 123 is allowed separately."
Add-EP "Windows - OS"           "Telemetry / Diagnostics"                "v10c.events.data.microsoft.com"         443 $true  "[2] EPM/IME" "SSL inspection NOT supported (EPM/IME telemetry endpoint)" $true
Add-EP "Windows - OS"           "Telemetry (Visual Studio)"              "dc.services.visualstudio.com"           443 $false "[MS] Telemetry" "" $true
Add-EP "Windows - OS"           "Client Config (P-Net)"                  "clientconfig.microsoftonline-p.net"     443 $false "[MS] Support Services" "" $true
Add-EP "Windows - OS"           "Device Health Attestation (Win10)"      "has.spserv.microsoft.com"               443 $false "[2] DHA Win10" "SSL inspection NOT supported (DHA endpoint)" $true

# ── MICROSOFT STORE [Ref 2] ─────────────────────────────────
Add-EP "Microsoft Store"        "Store Catalog"                          "displaycatalog.mp.microsoft.com"        443 $true  "[2] Store API" "SSL inspection NOT supported" $true
Add-EP "Microsoft Store"        "Store Purchase"                         "purchase.md.mp.microsoft.com"           443 $true  "[2] Store API" "SSL inspection NOT supported" $true
Add-EP "Microsoft Store"        "Store Licensing"                        "licensing.mp.microsoft.com"             443 $true  "[2] Store API" "SSL inspection NOT supported" $true
Add-EP "Microsoft Store"        "Store Edge CDN"                         "storeedgefd.dsx.mp.microsoft.com"       443 $true  "[2] Store API" "SSL inspection NOT supported" $true
Add-EP "Microsoft Store"        "Store Win32 CDN (fallback)"             "cdn.storeedgefd.dsx.mp.microsoft.com"   443 $true  "[2] Store Win32" "Win32 Store app fallback cache"

# ── INTUNE - REMOTE HELP [Ref 2 ID:181,187] ─────────────────
# Note: *.trouter.communication.microsoft.com and *.trouter.teams.microsoft.com
#       are also DR (ID:181) but are wildcards with no testable specific FQDNs in docs
Add-EP "Intune - Remote Help"   "Remote Help Portal"                     "remotehelp.microsoft.com"                                   443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Remote Assistance ACS (NA)"             "remoteassistanceprodacs.communication.azure.com"            443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Remote Assistance ACS (EU)"             "remoteassistanceprodacseu.communication.azure.com"          443 $true  "[2] ID:181" "EU tenants only"
Add-EP "Intune - Remote Help"   "Edge (Skype)"                           "edge.skype.com"                                             443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Edge (Microsoft)"                       "edge.microsoft.com"                                         443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "WCP Static"                             "wcpstatic.microsoft.com"                                    443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Support Services (RA)"                  "remoteassistance.support.services.microsoft.com"            443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Teams"                                  "teams.microsoft.com"                                        443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Aria Telemetry (browser)"               "browser.pipe.aria.microsoft.com"                            443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Monitor (JS)"                           "js.monitor.azure.com"                                       443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Flight Proxy (Skype)"                   "api.flightproxy.skype.com"                                  443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "ECS Communication"                      "ecs.communication.microsoft.com"                            443 $true  "[2] ID:181"
Add-EP "Intune - Remote Help"   "Trouter Cloud AMER (2026)"              "go-amer.trouter.communications.svc.cloud.microsoft"         443 $true  "[2] ID:181" "NA tenants - rolling out Mar-Jun 2026"
Add-EP "Intune - Remote Help"   "Trouter Cloud APAC (2026)"              "go-apac.trouter.communications.svc.cloud.microsoft"         443 $true  "[2] ID:181" "APAC tenants - rolling out Mar-Jun 2026"
Add-EP "Intune - Remote Help"   "Trouter Cloud EU (2026)"                "go-eu.trouter.communications.svc.cloud.microsoft"           443 $true  "[2] ID:181" "EU tenants - rolling out Mar-Jun 2026"
Add-EP "Intune - Remote Help"   "WebPubSub (RA Service)"                 "AMSUA0101-RemoteAssistService-pubsub.webpubsub.azure.com"   443 $true  "[2] ID:187"

# ── INTUNE - ANDROID AOSP [Ref 2 ID:179] ────────────────────
Add-EP "Intune - Android AOSP"  "AOSP CDN"                               "intunecdnpeasd.manage.microsoft.com"    443 $true  "[2] ID:179"

# ── CERTIFICATE VALIDATION / PKI ─────────────────────────────
Add-EP "PKI / CRL"             "Microsoft CRL"                          "crl.microsoft.com"                       80 $true  "[1][2]"
Add-EP "PKI / CRL"             "DigiCert CRL"                           "crl3.digicert.com"                       80 $false "[2]"
Add-EP "PKI / CRL"             "OCSP (DigiCert)"                        "ocsp.digicert.com"                       80 $true  "[2]"
Add-EP "PKI / CRL"             "OCSP (Microsoft)"                       "ocsp.msocsp.com"                         80 $true  "[2]"
Add-EP "PKI / CRL"             "Microsoft PKI (www)"                    "www.microsoft.com"                       80 $false "[2]"

# ══════════════════════════════════════════════════════════════
#  TEST FUNCTIONS (PS 5.1 + 7 compatible)
# ══════════════════════════════════════════════════════════════

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 4000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $task = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok = $task.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.EndConnect($task)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    }
    catch { return $false }
}

function Test-DnsResolve {
    param([string]$HostName)
    try {
        $result = [System.Net.Dns]::GetHostAddresses($HostName)
        if ($result.Count -gt 0) { return $result[0].IPAddressToString }
        return "FAILED"
    }
    catch { return "FAILED" }
}

function Test-PublicDns {
    param([string]$HostName)
    $canReach = Test-TcpPort -HostName "8.8.8.8" -Port 53 -TimeoutMs 2000
    if (-not $canReach) { return "External DNS blocked (port 53)" }
    try {
        $r = Resolve-DnsName -Name $HostName -Server "8.8.8.8" -Type A -ErrorAction Stop
        if ($r | Where-Object { $_.Type -in 'A', 'AAAA' }) { return "Local DNS cannot resolve (resolvable via 8.8.8.8)" }
    }
    catch {}
    return "Not publicly resolvable"
}

function Get-NetworkContext {
    # 1. IE/WinInet proxy (user context)
    $proxyEnabled = $false; $proxyServer = "-"; $wpadEnabled = $false
    try {
        $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA Stop
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $proxyEnabled = $true; $proxyServer = $ie.ProxyServer }
        if ($ie.AutoDetect -eq 1) { $wpadEnabled = $true }
    }
    catch {}

    # 2. WinHTTP proxy (SYSTEM context — relevant for Intune agent traffic)
    $winHTTPProxy = "-"
    try {
        $winhttpOut = cmd /c "netsh winhttp show proxy" 2>$null
        $pLine = @($winhttpOut) | Where-Object { $_ -match 'Proxy Server' } | Select-Object -First 1
        if ($pLine) {
            $m = [regex]::Match($pLine, ':\s*(.+)$')
            if ($m.Success) { $winHTTPProxy = $m.Groups[1].Value.Trim() }
        }
    }
    catch {}

    # 3. VPN adapter detection
    $vpnDetected = $false; $vpnAdapter = "-"
    try {
        $kw = @("VPN", "Tunnel", "TAP-Win", "Cisco", "GlobalProtect", "Pulse", "FortiClient", "OpenVPN", "WireGuard", "AnyConnect", "ZScaler", "Zscaler", "NordVPN", "ExpressVPN")
        $vpnNic = Get-NetAdapter -EA Stop | Where-Object {
            $d = $_.InterfaceDescription; $a = $_.InterfaceAlias
            $_.Status -eq "Up" -and ($kw | Where-Object { $d -like "*$_*" -or $a -like "*$_*" }).Count -gt 0
        } | Select-Object -First 1
        if ($vpnNic) { $vpnDetected = $true; $vpnAdapter = "$($vpnNic.Name) — $($vpnNic.InterfaceDescription)" }
    }
    catch {}

    # 4. Active DNS servers — if RFC1918 range, corporate DNS is likely active
    $dnsServers = "-"; $privateDNS = $false
    try {
        $servers = @(Get-DnsClientServerAddress -EA Stop |
            Where-Object { $_.AddressFamily -eq 2 -and $_.ServerAddresses.Count -gt 0 } |
            ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        if ($servers.Count -gt 0) {
            $dnsServers = $servers -join ", "
            $privPat = @("^10\.", "^172\.(1[6-9]|2[0-9]|3[0-1])\.", "^192\.168\.")
            $privateDNS = ($servers | Where-Object {
                    $ip = $_; ($privPat | Where-Object { $ip -match $_ }).Count -gt 0
                }).Count -gt 0
        }
    }
    catch {}

    # 5. SCHANNEL TLS protocol status (OS-level registry — authoritative source)
    $schannelSummary = "-"; $schannelWarn = $false
    try {
        $schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
        $tlsChecks = [ordered]@{ "1.0" = $false; "1.1" = $false; "1.2" = $false; "1.3" = $false }
        foreach ($ver in $tlsChecks.Keys) {
            $path = "$schannelBase\TLS $ver\Client"
            try {
                $p = Get-ItemProperty -Path $path -EA Stop
                # Enabled=0 means explicitly disabled; anything else (1 or absent) = enabled
                $tlsChecks[$ver] = ($p.Enabled -ne 0)
            }
            catch {
                # Key absent = OS default: enabled (conservative assumption)
                $tlsChecks[$ver] = $true
            }
        }
        $parts = $tlsChecks.Keys | ForEach-Object { "TLS ${_}: $(if ($tlsChecks[$_]) { 'ON' } else { 'OFF' })" }
        $schannelSummary = $parts -join " | "
        # Warn if 1.0 or 1.1 is ON, or if 1.2 AND 1.3 are both OFF
        $schannelWarn = $tlsChecks["1.0"] -or $tlsChecks["1.1"] -or (-not $tlsChecks["1.2"] -and -not $tlsChecks["1.3"])
    }
    catch {}

    [PSCustomObject]@{
        ProxyEnabled       = $proxyEnabled
        ProxyServer        = $proxyServer
        WinHTTPProxy       = $winHTTPProxy
        WPADEnabled        = $wpadEnabled
        VPNDetected        = $vpnDetected
        VPNAdapter         = $vpnAdapter
        DNSServers         = $dnsServers
        CorporateDNSLikely = $privateDNS
        DotNetTLS          = $schannelSummary
        DotNetTLSWarn      = $schannelWarn
        ServicePointTLS    = $(try { [System.Net.ServicePointManager]::SecurityProtocol.ToString() } catch { "Unknown" })
        ServicePointWarn   = $(try { [System.Net.ServicePointManager]::SecurityProtocol.ToString() -notmatch "Tls12|Tls13" } catch { $true })
    }
}

function Test-TlsHandshake {
    param([string]$HostName, [int]$Port = 443)
    if ($Port -ne 443) { return "N/A (HTTP)" }
    # Test protocols from newest to oldest — detects what client machine can negotiate
    $protos = @(
        [System.Security.Authentication.SslProtocols]::Tls13,
        [System.Security.Authentication.SslProtocols]::Tls12,
        [System.Security.Authentication.SslProtocols]::Tls11,
        [System.Security.Authentication.SslProtocols]::Tls      # TLS 1.0
    )
    foreach ($proto in $protos) {
        $tcp = $null; $ssl = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false,
                ([System.Net.Security.RemoteCertificateValidationCallback] { $true }))
            $ssl.AuthenticateAsClient($HostName, $null, $proto, $false)
            $negotiated = $ssl.SslProtocol
            $issuer = $ssl.RemoteCertificate.Issuer
            if ($issuer -match "O=([^,]+)") { $issuer = $Matches[1] }
            $ssl.Close(); $tcp.Close()
            $advisory = switch -Regex ($negotiated.ToString()) {
                "Tls13|Tls12" { "" }
                "Tls11" { " — upgrade recommended" }
                default { " — CHANGE NEEDED (use TLS 1.2+)" }
            }
            return "$negotiated | $issuer$advisory"
        }
        catch {
            if ($ssl) { try { $ssl.Close() } catch {} }
            if ($tcp) { try { $tcp.Close() } catch {} }
        }
    }
    return "FAILED"
}

# ══════════════════════════════════════════════════════════════
#  EXECUTION
# ══════════════════════════════════════════════════════════════

Clear-Host
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   Entra ID & Intune Connectivity Checker v2.1" -ForegroundColor Cyan
Write-Host "   Author: [Marcin Nadlewski]  |  Version: 2.1 | 2026-04-03" -ForegroundColor DarkCyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $env:COMPUTERNAME | PS $($PSVersionTable.PSVersion)" -ForegroundColor DarkCyan
Write-Host "   User: $env:USERDOMAIN\$env:USERNAME | Admin: $(if ($IsAdmin) { 'YES' } else { 'NO' })" -ForegroundColor DarkCyan
Write-Host "   Region: $Region | Endpoints: $($Endpoints.Count)" -ForegroundColor DarkCyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

# ══════════════════════════════════════════════════════════════
#  NETWORK ENVIRONMENT CONTEXT (computed here, displayed after results)
# ══════════════════════════════════════════════════════════════
$NetworkCtx = Get-NetworkContext
$_ctxParts = @()
if ($NetworkCtx.VPNDetected) { $_ctxParts += "VPN:$($NetworkCtx.VPNAdapter.Split('—')[0].Trim())" }
if ($NetworkCtx.ProxyEnabled) { $_ctxParts += "Proxy(IE):$($NetworkCtx.ProxyServer)" }
elseif ($NetworkCtx.WinHTTPProxy -ne "-") { $_ctxParts += "Proxy(WinHTTP):$($NetworkCtx.WinHTTPProxy)" }
if ($NetworkCtx.CorporateDNSLikely) { $_ctxParts += "CorpDNS:$($NetworkCtx.DNSServers.Split(',')[0].Trim())" }
$TestContextStr = if ($_ctxParts.Count -gt 0) { $_ctxParts -join " | " } else { "Direct (no VPN/proxy detected)" }

# ══════════════════════════════════════════════════════════════
#  $Results - "DID IT WORK?"
#  DIAGNOSTIC DATA - Shows what happened when testing
#  Contains: DNS resolution, TCP connectivity, TLS handshake
#  Purpose: Troubleshooting connectivity problems
# ══════════════════════════════════════════════════════════════
$Results = [System.Collections.ArrayList]::new()
$total = $Endpoints.Count
$i = 0

foreach ($ep in $Endpoints) {
    $i++
    $pct = [math]::Round($i / $total * 100)
    Write-Host "`r  [$pct%] ($i/$total) Testing: $($ep.URL):$($ep.Port)                              " -NoNewline -ForegroundColor DarkGray

    $dns = Test-DnsResolve -HostName $ep.URL
    $dnsPublic = if ($dns -eq "FAILED") {
        if ($ep.WildcardRule -ne "-") { "Not a standalone host — configure $($ep.WildcardRule)" }
        else { Test-PublicDns -HostName $ep.URL }
    }
    else { "-" }
    $tcp = Test-TcpPort -HostName $ep.URL -Port $ep.Port
    $tls = if ($tcp) { Test-TlsHandshake -HostName $ep.URL -Port $ep.Port } else { "N/A" }

    $status = if ($dns -eq "FAILED") { "DNS_FAIL" }
    elseif (-not $tcp) { "TCP_BLOCKED" }
    elseif ($tls -eq "FAILED" -and $ep.Port -eq 443) { "TLS_FAIL" }
    else { "OK" }

    [void]$Results.Add([PSCustomObject]@{
            RunByUser             = $RunByUser
            Admin                 = if ($IsAdmin) { "YES" } else { "NO" }
            GeoRegion             = $ep.GeoRegion
            Category              = $ep.Category
            Name                  = $ep.Name
            Endpoint              = "$($ep.URL):$($ep.Port)"
            DNS_IP                = $dns
            DNS_Public            = $dnsPublic
            TCP                   = if ($tcp) { "Open" } else { "Blocked" }
            TLS                   = $tls
            Status                = $status
            OS_TLS                = $NetworkCtx.DotNetTLS
            DotNet_TLS_Powershell = $NetworkCtx.ServicePointTLS
            Critical              = if ($ep.Critical) { "YES" } else { "no" }
            Action_SSL            = if ($ep.NoSSLInspection -and $status -eq "TLS_FAIL") { "SSL inspection DETECTED — configure bypass (MS docs)" }
            elseif ($ep.NoSSLInspection) { "Verify SSL bypass is set (MS docs)" }
            else { "-" }
            Action_Proxy          = if ($ep.ProxyUnauth) { "Verify unauthenticated proxy access is set (MS docs)" } else { "-" }
            Ref                   = $ep.Ref
            Note                  = $ep.Note
            WildcardRule          = $ep.WildcardRule
            TestContext           = $TestContextStr
            
        })
}

Write-Host "`r  [100%] Done. Tested $total endpoints.                                       " -ForegroundColor Green
Write-Host ""

# ── Summary Counts ──
$passCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
$failCount = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" -and $_.DNS_Public -ne "Not publicly resolvable" }).Count
$warnCount = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "no" -and $_.DNS_Public -ne "Not publicly resolvable" }).Count

Write-Host "  +-----------------------------------------+" -ForegroundColor White
Write-Host "  |  RESULTS:  " -NoNewline -ForegroundColor White
Write-Host "$passCount PASS" -NoNewline -ForegroundColor Green
Write-Host "  |  " -NoNewline -ForegroundColor White
Write-Host "$failCount CRITICAL FAIL" -NoNewline -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "  |  " -NoNewline -ForegroundColor White
Write-Host "$warnCount WARN" -NoNewline -ForegroundColor $(if ($warnCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  |" -ForegroundColor White
Write-Host "  +-----------------------------------------+" -ForegroundColor White
Write-Host ""

# ── Display per category ──
foreach ($cat in ($Results | Select-Object -ExpandProperty Category -Unique)) {
    Write-Host "  -- $cat --" -ForegroundColor Cyan
    $catResults = $Results | Where-Object { $_.Category -eq $cat }

    foreach ($r in $catResults) {
        $icon = switch ($r.Status) {
            "OK" { "[PASS] " }
            "DNS_FAIL" { "[DNS!] " }
            "TCP_BLOCKED" { "[BLOCK]" }
            "TLS_FAIL" { "[TLS!] " }
        }
        $color = switch ($r.Status) {
            "OK" { if ($r.Critical -eq "YES") { "Green" } else { "DarkGreen" } }
            default { if ($r.Critical -eq "YES") { "Red" } else { "Yellow" } }
        }
        $crit = if ($r.Critical -eq "YES") { "*" } else { " " }
        $line = "  {0} {1}{2,-44} {3,-52} {4,-8} {5}" -f $icon, $crit, $r.Name, $r.Endpoint, $r.TCP, $r.DNS_IP
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ""
}

# ── Legend ──
Write-Host "  * = Critical endpoint (required for hybrid join / MDM enrollment)" -ForegroundColor DarkGray
Write-Host "  Ref [1] = Entra hybrid join doc  |  Ref [2] = Intune endpoints doc" -ForegroundColor DarkGray
Write-Host ""

# ── Critical failures detail ──
$critFails = $Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" -and $_.DNS_Public -ne "Not publicly resolvable" }
if ($critFails) {
    Write-Host "  !! ACTION REQUIRED - Critical endpoints failing:" -ForegroundColor Red
    Write-Host "  -------------------------------------------------" -ForegroundColor Red
    foreach ($f in $critFails) {
        Write-Host "     [$($f.Status)] $($f.Endpoint) - $($f.Name)" -ForegroundColor Red
        if ($f.Note) { Write-Host "              Note: $($f.Note)" -ForegroundColor DarkYellow }
    }
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "    1. Ensure firewall/proxy allows outbound to above endpoints" -ForegroundColor Yellow
    Write-Host "    2. Exempt *.manage.microsoft.com and login.microsoftonline.com from SSL inspection" -ForegroundColor Yellow
    Write-Host "    3. Ensure SYSTEM account has network access (no proxy auth for machine context)" -ForegroundColor Yellow
    Write-Host "    4. Verify DNS resolves correctly from this machine" -ForegroundColor Yellow
    Write-Host ""
}

# ── Not publicly resolvable (informational) ──
if ($UnresolvableHosts.Count -gt 0) {
    Write-Host "  ℹ️  INFO - Endpoints not resolvable via public DNS (no action needed):" -ForegroundColor DarkGray
    Write-Host "  -----------------------------------------------------------------------" -ForegroundColor DarkGray
    foreach ($f in $UnresolvableHosts) {
        Write-Host "     [DNS_FAIL / not publicly resolvable] $($f.Endpoint) - $($f.Name)" -ForegroundColor DarkGray
    }
    Write-Host "     These endpoints do not exist in public DNS — DNS_FAIL is expected." -ForegroundColor DarkGray
    Write-Host "     They are excluded from CRITICAL and WARN counts. No action required." -ForegroundColor DarkGray
    Write-Host ""
}

# ── TLS Inspection Warning ──
$tlsFails = $Results | Where-Object { $_.Status -eq "TLS_FAIL" }
if ($tlsFails) {
    Write-Host "  !! TLS HANDSHAKE FAILURES DETECTED:" -ForegroundColor Magenta
    Write-Host "     This may indicate SSL/TLS inspection (proxy break-and-inspect)." -ForegroundColor Magenta
    Write-Host "     Microsoft requires these domains to be excluded from TLS inspection:" -ForegroundColor Magenta
    Write-Host "       - *.manage.microsoft.com" -ForegroundColor Magenta
    Write-Host "       - *.dm.microsoft.com" -ForegroundColor Magenta
    Write-Host "       - device.login.microsoftonline.com" -ForegroundColor Magenta
    Write-Host "       - enterpriseregistration.windows.net" -ForegroundColor Magenta
    Write-Host ""
}

# ── Non-Microsoft TLS issuers (proxy detection) ──
$proxyDetected = $Results | Where-Object {
    $_.TLS -ne "N/A" -and $_.TLS -ne "N/A (HTTP)" -and $_.TLS -ne "FAILED" -and
    $_.TLS -notmatch "Microsoft|DigiCert|Baltimore|GlobalSign|Symantec|GeoTrust|Lets Encrypt|Amazon|Akamai|Cloudflare|Google"
}
if ($proxyDetected) {
    Write-Host "  !! POSSIBLE SSL INSPECTION DETECTED on these endpoints:" -ForegroundColor Magenta
    foreach ($p in $proxyDetected) {
        Write-Host "     $($p.Endpoint) -> Issuer: $($p.TLS)" -ForegroundColor Magenta
    }
    Write-Host "     Non-Microsoft certificate issuers may indicate proxy interception." -ForegroundColor Magenta
    Write-Host ""
}

# ── CSV Export ──
if ($ExportCSV) {
    $Results | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV exported: $CSVPath" -ForegroundColor Green
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════
#  NETWORK REQUIREMENTS SUMMARY TABLE
# ══════════════════════════════════════════════════════════════

Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   NETWORK REQUIREMENTS SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

# ══════════════════════════════════════════════════════════════
#  $SummaryTable - "WHAT DO I NEED?"
#  CONFIGURATION DATA - Lists what should be allowed in firewall
#  Contains: Unique endpoints (deduplicated), no test results
#  Purpose: Configuring network/firewall rules
# ══════════════════════════════════════════════════════════════
$SummaryTable = [System.Collections.ArrayList]::new()
$processedEndpoints = @{}

foreach ($ep in $Endpoints | Sort-Object Category, URL, Port) {
    $key = "$($ep.URL):$($ep.Port)"
    
    # Only add unique endpoints
    if (-not $processedEndpoints.ContainsKey($key)) {
        $processedEndpoints[$key] = $true
        
        # Determine protocol
        $protocol = if ($ep.Port -eq 443) { "HTTPS" } 
        elseif ($ep.Port -eq 80) { "HTTP" }
        else { "TCP" }
        
        [void]$SummaryTable.Add([PSCustomObject]@{
                RunByUser    = $RunByUser
                Admin        = if ($IsAdmin) { "YES" } else { "NO" }
                GeoRegion    = $ep.GeoRegion
                Category     = $ep.Category
                URL          = $ep.URL
                Port         = $ep.Port
                Protocol     = $protocol
                Critical     = if ($ep.Critical) { "YES" } else { "No" }
                Action_SSL   = if ($ep.NoSSLInspection) { "Verify SSL bypass is set (MS docs)" } else { "-" }
                Action_Proxy = if ($ep.ProxyUnauth) { "Verify unauthenticated proxy access is set (MS docs)" } else { "-" }
                Purpose      = $ep.Name
                Reference    = $ep.Ref
                Notes        = $ep.Note
            })
    }
}

Write-Host "  Total unique network requirements: $($SummaryTable.Count) endpoints" -ForegroundColor White
Write-Host ""

# ══════════════════════════════════════════════════════════════
#  $BasicRequired - "WHAT MUST BYPASS SSL INSPECTION?"
#  CRITICAL SECURITY CONFIG - Endpoints that WILL FAIL if proxied
#  Contains: Endpoints requiring SSL/TLS inspection bypass
#  Purpose: Configuring proxy exclusions / SSL bypass rules
# ══════════════════════════════════════════════════════════════

$BasicRequired = [System.Collections.ArrayList]::new()

# Filter endpoints that require SSL/TLS bypass from both Results and SummaryTable
$noSSLInspectionEndpoints = $Results | Where-Object { $_.Action_SSL -ne "-" }

foreach ($endpoint in $noSSLInspectionEndpoints) {
    [void]$BasicRequired.Add([PSCustomObject]@{
            RunByUser  = $endpoint.RunByUser
            Admin      = $endpoint.Admin
            Category   = $endpoint.Category
            Name       = $endpoint.Name
            Endpoint   = $endpoint.Endpoint
            URL        = ($endpoint.Endpoint -split ':')[0]
            Port       = ($endpoint.Endpoint -split ':')[1]
            DNS_IP     = $endpoint.DNS_IP
            TCP        = $endpoint.TCP
            TLS        = $endpoint.TLS
            Status     = $endpoint.Status
            Critical   = $endpoint.Critical
            Action_SSL = $endpoint.Action_SSL
            Ref        = $endpoint.Ref
            Note       = $endpoint.Note
        })
}

Write-Host "  ⚠️  CRITICAL: $($BasicRequired.Count) endpoints require SSL/TLS inspection bypass" -ForegroundColor Magenta
Write-Host ""

# ══════════════════════════════════════════════════════════════
#  $ProxyRequired - "WHAT NEEDS UNAUTHENTICATED PROXY ACCESS?"
#  CONFIGURATION DATA - Endpoints that must reach internet directly
#  without proxy authentication (SYSTEM account context)
#  Source: MS docs - manage.microsoft.com, *.azureedge.net, graph.microsoft.com
#  Note: *.azureedge.net (CDN) is also required but can't be tested directly
# ══════════════════════════════════════════════════════════════
$ProxyRequired = @($SummaryTable | Where-Object { $_.Action_Proxy -ne "-" })

# ══════════════════════════════════════════════════════════════
#  $ActionReport - CONSOLIDATED SINGLE-PANE-OF-GLASS VIEW
#  All endpoints that need ANY action: unblock (live test), SSL bypass or proxy (MS docs).
#  Use: $ActionReport | Out-GridView
# ══════════════════════════════════════════════════════════════
$ActionReport = @($Results | ForEach-Object {
        $fwAction = if ($_.Status -eq "TCP_BLOCKED" -and $_.Note -match "expected") {
            "-"  # Expected TCP_BLOCKED (e.g. NTP UDP port tested via TCP — normal behaviour)
        }
        elseif ($_.WildcardRule -ne "-" -and $_.Status -in "DNS_FAIL", "TCP_BLOCKED") {
            "DNS FAIL — configure $($_.WildcardRule) on firewall"  # Bare wildcard base domain
        }
        elseif ($_.Status -in "DNS_FAIL", "TCP_BLOCKED") {
            if ($_.DNS_Public -eq "Not publicly resolvable") { "-" }
            elseif ($_.DNS_Public -eq "Local DNS cannot resolve (resolvable via 8.8.8.8)") {
                "DNS Resolution Failed (Endpoint may not be a standalone host)"
            }
            elseif ($_.Critical -eq "YES") { "UNBLOCK — connection failed (CRITICAL)" }
            else { "UNBLOCK — connection failed (WARNING)" }
        }
        else { "-" }  # TLS_FAIL → action is SSL bypass (Action_SSL), not firewall unblock
        if ($fwAction -ne "-" -or $_.Action_SSL -ne "-" -or $_.Action_Proxy -ne "-") {
            [PSCustomObject]@{
                Category              = $_.Category
                Name                  = $_.Name
                Endpoint              = $_.Endpoint
                Status                = $_.Status
                Critical              = $_.Critical
                Firewall_Action       = $fwAction
                Wildcard_Rule         = $_.WildcardRule
                Action_SSL            = $_.Action_SSL
                Action_Proxy          = $_.Action_Proxy
                OS_TLS                = $_.OS_TLS
                DotNet_TLS_Powershell = $_.DotNet_TLS_Powershell
                DNS_IP                = $_.DNS_IP
                DNS_Public            = $_.DNS_Public
                TCP                   = $_.TCP
                Note                  = $_.Note
                
            }
        }
    } | Where-Object { $_ -ne $null })

$UnresolvableHosts = @($Results | Where-Object { $_.DNS_Public -eq "Not publicly resolvable" })
$BlockedResults = @($Results | Where-Object { $_.Status -ne "OK" -and $_.DNS_Public -ne "Not publicly resolvable" })

Write-Host "  ℹ️  INFO: $($ProxyRequired.Count) endpoints require unauthenticated proxy access" -ForegroundColor DarkYellow
Write-Host "     ► manage.microsoft.com, *.manage.microsoft.com, graph.microsoft.com" -ForegroundColor DarkGray
Write-Host "     ► Also: *.azureedge.net (CDN - wildcard, not directly testable)" -ForegroundColor DarkGray
Write-Host ""

# Display summary grouped by category
foreach ($cat in ($SummaryTable | Select-Object -ExpandProperty Category -Unique)) {
    Write-Host "  ┌─ $cat " -ForegroundColor Yellow
    $catSummary = $SummaryTable | Where-Object { $_.Category -eq $cat }
    
    foreach ($item in $catSummary) {
        $critMarker = if ($item.Critical -eq "YES") { "*" } else { " " }
        $portProtocol = "$($item.Port)/$($item.Protocol)"
        Write-Host "  │ $critMarker " -NoNewline -ForegroundColor $(if ($item.Critical -eq "YES") { "Red" } else { "Gray" })
        Write-Host "$($item.URL)" -NoNewline -ForegroundColor White
        Write-Host " : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$portProtocol" -NoNewline -ForegroundColor Cyan
        if ($item.Notes) {
            Write-Host " ($($item.Notes))" -ForegroundColor DarkYellow
        }
        else {
            Write-Host ""
        }
    }
    Write-Host ""
}

Write-Host "  * = Critical endpoint (must be accessible)" -ForegroundColor DarkGray
Write-Host ""

# Quick reference for firewall rules
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   FIREWALL CONFIGURATION QUICK REFERENCE" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

$portSummary = $SummaryTable | Group-Object Port | Sort-Object Name
Write-Host "  Ports to open (outbound):" -ForegroundColor Yellow
foreach ($port in $portSummary) {
    $protocol = ($port.Group | Select-Object -First 1).Protocol
    $count = $port.Count
    Write-Host "    - Port $($port.Name)/$protocol" -NoNewline -ForegroundColor White
    Write-Host " ($count endpoints)" -ForegroundColor DarkGray
}
Write-Host ""

# Wildcard domains for easier firewall configuration
Write-Host "  Recommended wildcard domain rules:" -ForegroundColor Yellow
$wildcards = @(
    "*.manage.microsoft.com",
    "*.microsoft.com",
    "*.microsoftonline.com",
    "*.windows.net",
    "*.windows.com",
    "*.attest.azure.net",
    "*.core.windows.net",
    "*.digicert.com",
    "*.msauth.net",
    "*.msftauth.net",
    "*.azure.com"
)
foreach ($wc in $wildcards) {
    Write-Host "    - $wc" -ForegroundColor White
}
Write-Host ""

Write-Host "  Important notes:" -ForegroundColor Yellow
Write-Host "    1. SSL/TLS inspection must be DISABLED for the following endpoints:" -ForegroundColor White
Write-Host "       (These are marked as 'Action_SSL != -' in exported CSV)" -ForegroundColor DarkGray
Write-Host ""
$noSSLEndpoints = $SummaryTable | Where-Object { $_.Action_SSL -ne "-" } | Select-Object -ExpandProperty URL -Unique
foreach ($endpoint in $noSSLEndpoints) {
    Write-Host "       - $endpoint" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "    2. Proxy authentication must not be required for SYSTEM account" -ForegroundColor White
Write-Host "       Intune requires unauthenticated proxy access to:" -ForegroundColor DarkGray
Write-Host "         manage.microsoft.com  |  *.azureedge.net  |  graph.microsoft.com" -ForegroundColor Cyan
Write-Host "       Use: `$ProxyRequired | Out-GridView  to see all flagged endpoints" -ForegroundColor DarkGray
Write-Host "    3. Allow both IPv4 and IPv6 if available" -ForegroundColor White
Write-Host "    4. Azure Front Door (AzureFrontDoor.MicrosoftSecurity) is used by Intune." -ForegroundColor White
Write-Host "       IP ranges: 13.107.219.0/24, 13.107.227-228.x, 150.171.97.0/24 (+ IPv6)" -ForegroundColor DarkGray
Write-Host "       Download latest: https://www.microsoft.com/en-us/download/details.aspx?id=56519" -ForegroundColor DarkGray
Write-Host ""

# ── Export Summary Table to CSV ──
if ($ExportSummaryTable) {
    $SummaryTable | Export-Csv -Path $SummaryCSVPath -NoTypeInformation -Encoding UTF8
    Write-Host "  Network Requirements Summary CSV exported: $SummaryCSVPath" -ForegroundColor Green
    Write-Host ""
}

# Display instructions if user didn't export
if (-not $ExportSummaryTable -and -not $ExportCSV -and -not $ExportHTML) {
    Write-Host "  Tip: Use -ExportHTML to generate a full HTML report with action guidance" -ForegroundColor DarkGray
    Write-Host "       .\connectivity_checker_simplified.ps1 -ExportHTML" -ForegroundColor Cyan
    Write-Host "       Or from current session: Export-HTMLReport -Path `"`$env:USERPROFILE\Desktop\ConnectivityReport.html`"" -ForegroundColor Cyan
    Write-Host "       Use -ExportSummaryTable to export network requirements to CSV" -ForegroundColor DarkGray
    Write-Host "       Use -ExportCSV to export connectivity test results to CSV" -ForegroundColor DarkGray
    Write-Host ""
}

# ── Return results for pipeline ──
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   SCRIPT COMPLETED - Data Available in Variables" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Variables created:" -ForegroundColor White
Write-Host "    `$Results         - Connectivity test results ($($Results.Count) tests)" -ForegroundColor Green
Write-Host "    `$SummaryTable    - Network requirements summary ($($SummaryTable.Count) unique endpoints)" -ForegroundColor Green
Write-Host "    `$BasicRequired   - SSL/TLS bypass required endpoints ($($BasicRequired.Count) critical)" -ForegroundColor Magenta
Write-Host "    `$ProxyRequired   - Unauthenticated proxy access required ($($ProxyRequired.Count) endpoints)" -ForegroundColor DarkYellow
Write-Host "    `$ActionReport    - ⚡ Consolidated action view ($($ActionReport.Count) endpoints needing action)" -ForegroundColor Cyan
Write-Host "    `$BlockedResults  - Actionable failures only — excludes 'not publicly resolvable' ($($BlockedResults.Count))" -ForegroundColor Yellow
Write-Host "    `$UnresolvableHosts - Endpoints not resolvable via public DNS — informational, no action needed ($($UnresolvableHosts.Count))" -ForegroundColor DarkGray
Write-Host "    `$NetworkCtx      - Network environment context (VPN, proxy, DNS servers)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Quick commands:" -ForegroundColor Yellow
Write-Host "    `$ActionReport | Out-GridView   # ⚡ CONSOLIDATED: all blocked + SSL + proxy issues" -ForegroundColor Green
Write-Host "    `$Results | Out-GridView        # Full connectivity test results" -ForegroundColor Cyan
Write-Host "    `$BlockedResults | Out-GridView  # Actionable failures only (excludes 'not publicly resolvable')" -ForegroundColor Yellow
Write-Host "    `$UnresolvableHosts | Out-GridView  # Endpoints not resolvable via Google DNS (informational)" -ForegroundColor DarkGray
Write-Host "    `$SummaryTable | Out-GridView   # Network requirements" -ForegroundColor Cyan
Write-Host "    `$BasicRequired | Out-GridView  # Endpoints requiring SSL/TLS bypass" -ForegroundColor Magenta
Write-Host "    `$ProxyRequired | Out-GridView  # Endpoints needing unauthenticated proxy access" -ForegroundColor DarkYellow
Write-Host ""

# Output formatted data for better display
Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  CONNECTIVITY TEST SUMMARY                                      │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# Summary stats table
$summaryStats = [PSCustomObject]@{
    'Total Endpoints Tested'                   = $Endpoints.Count
    'Passed'                                   = ($Results | Where-Object { $_.Status -eq "OK" }).Count
    'Critical Failures'                        = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "YES" -and $_.DNS_Public -ne "Not publicly resolvable" }).Count
    'Warnings'                                 = ($Results | Where-Object { $_.Status -ne "OK" -and $_.Critical -eq "no" -and $_.DNS_Public -ne "Not publicly resolvable" }).Count
    'Not Publicly Resolvable (informational)'  = $UnresolvableHosts.Count
    'Unique URLs Required'                     = $SummaryTable.Count
    'SSL Bypass Required (MS docs)'            = $BasicRequired.Count
    'Proxy Unauthenticated Required (MS docs)' = $ProxyRequired.Count
    'Region'                                   = $Region
}
$summaryStats | Format-List

Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  CONNECTIVITY TEST RESULTS (Top 20)                             │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
$Results | Select-Object -First 20 Category, Name, Endpoint, Status, TCP, Critical | Format-Table -AutoSize

if ($Results.Count -gt 20) {
    Write-Host "  ... and $($Results.Count - 20) more results. Use `$Results | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  NETWORK REQUIREMENTS (Top 20)                                  │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
$SummaryTable | Select-Object -First 20 Category, URL, Port, Protocol, Critical | Format-Table -AutoSize

if ($SummaryTable.Count -gt 20) {
    Write-Host "  ... and $($SummaryTable.Count - 20) more requirements. Use `$SummaryTable | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  BASIC REQUIRED ENDPOINTS (SSL/TLS Bypass Required)             │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
$BasicRequired | Select-Object -First 15 Name, Endpoint, Status, TCP, Action_SSL | Format-Table -AutoSize

if ($BasicRequired.Count -gt 15) {
    Write-Host "  ... and $($BasicRequired.Count - 15) more endpoints. Use `$BasicRequired | Out-GridView to see all" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  📊 WHICH TABLE SHOULD I USE? - QUICK REFERENCE" -ForegroundColor Yellow
Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  TABLE 1: `$Results = `"DID IT WORK?`"                           │" -ForegroundColor Cyan
Write-Host "  └────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "     📋 WHAT IT IS:" -ForegroundColor White
Write-Host "        • DIAGNOSTIC DATA - Shows what happened when testing" -ForegroundColor Gray
Write-Host "        • Contains: DNS resolution, TCP connectivity, TLS handshake" -ForegroundColor Gray
Write-Host "        • Purpose: Troubleshooting connectivity problems" -ForegroundColor Gray
Write-Host ""
Write-Host "     🎯 WHEN TO USE:" -ForegroundColor White
Write-Host "        • Finding what's broken (which endpoints failed)" -ForegroundColor Gray
Write-Host "        • Seeing WHY it failed (DNS? Firewall? SSL?)" -ForegroundColor Gray
Write-Host "        • Creating troubleshooting reports for IT team" -ForegroundColor Gray
Write-Host ""
Write-Host "     💻 EXAMPLE:" -ForegroundColor White
Write-Host "        `$Results | Out-GridView                            # View all" -ForegroundColor Yellow
Write-Host "        `$BlockedResults | Out-GridView                   # Actionable failures only" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  TABLE 2: `$SummaryTable = `"WHAT DO I NEED?`"                  │" -ForegroundColor Cyan
Write-Host "  └────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "     📋 WHAT IT IS:" -ForegroundColor White
Write-Host "        • CONFIGURATION DATA - Lists what should be allowed in firewall" -ForegroundColor Gray
Write-Host "        • Contains: Unique endpoints (deduplicated), no test results" -ForegroundColor Gray
Write-Host "        • Purpose: Configuring network/firewall rules" -ForegroundColor Gray
Write-Host ""
Write-Host "     🎯 WHEN TO USE:" -ForegroundColor White
Write-Host "        • Requesting firewall openings from network team" -ForegroundColor Gray
Write-Host "        • Creating allowlist for proxy/firewall" -ForegroundColor Gray
Write-Host "        • Documenting network dependencies" -ForegroundColor Gray
Write-Host ""
Write-Host "     💻 EXAMPLE:" -ForegroundColor White
Write-Host "        `$SummaryTable | Out-GridView                                # View all" -ForegroundColor Yellow
Write-Host "        `$SummaryTable | Where Critical -eq 'YES' | Out-GridView     # Critical only" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  TABLE 3: `$BasicRequired = `"WHAT MUST BYPASS SSL?`"           │" -ForegroundColor Cyan
Write-Host "  └────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "     📋 WHAT IT IS:" -ForegroundColor White
Write-Host "        • CRITICAL SECURITY CONFIG - Endpoints that WILL FAIL if proxied" -ForegroundColor Gray
Write-Host "        • Contains: Endpoints requiring SSL/TLS inspection bypass" -ForegroundColor Gray
Write-Host "        • Purpose: Configuring proxy exclusions / SSL bypass rules" -ForegroundColor Gray
Write-Host ""
Write-Host "     🎯 WHEN TO USE:" -ForegroundColor White
Write-Host "        • Configuring SSL bypass on proxy/firewall" -ForegroundColor Gray
Write-Host "        • Troubleshooting `"device won't join Entra`" issues" -ForegroundColor Gray
Write-Host "        • Fixing MDM enrollment failures" -ForegroundColor Gray
Write-Host ""
Write-Host "     💻 EXAMPLE:" -ForegroundColor White
Write-Host "        `$BasicRequired | Out-GridView                               # View all" -ForegroundColor Yellow
Write-Host "        `$BasicRequired | Select URL -Unique                         # Get unique URLs" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
Write-Host "  │  TABLE 4: `$ProxyRequired = `"WHAT NEEDS PROXY BYPASS?`"        │" -ForegroundColor DarkYellow
Write-Host "  └────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "     📋 WHAT IT IS:" -ForegroundColor White
Write-Host "        • PROXY CONFIG DATA - Endpoints requiring unauthenticated access" -ForegroundColor Gray
Write-Host "        • MS docs: manage.microsoft.com, *.azureedge.net, graph.microsoft.com" -ForegroundColor Gray
Write-Host "        • Purpose: Configuring proxy bypass / unauthenticated access rules" -ForegroundColor Gray
Write-Host ""
Write-Host "     🎯 WHEN TO USE:" -ForegroundColor White
Write-Host "        • Configuring proxy to allow unauthenticated SYSTEM access" -ForegroundColor Gray
Write-Host "        • Troubleshooting enrollment failures in proxy environments" -ForegroundColor Gray
Write-Host "        • Giving network team the list of endpoints to allow unauthenticated" -ForegroundColor Gray
Write-Host ""
Write-Host "     ⚠️  IMPORTANT:" -ForegroundColor White
Write-Host "        • *.azureedge.net is also required but wildcard - cannot be DNS-tested" -ForegroundColor Gray
Write-Host "        • SYSTEM account context - standard user proxy auth does NOT apply" -ForegroundColor Gray
Write-Host ""
Write-Host "     💻 EXAMPLE:" -ForegroundColor White
Write-Host "        `$ProxyRequired | Out-GridView                              # View all" -ForegroundColor Yellow
Write-Host "        `$Results | Where Action_Proxy -ne '-' | Out-GridView # Test status" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "  📌 QUICK ACTIONS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "     ⚡ CONSOLIDATED ACTION REPORT (single pane — blocked + SSL + proxy):" -ForegroundColor White
Write-Host "     » `$ActionReport | Out-GridView" -ForegroundColor Green
Write-Host "     » `$ActionReport | Out-GridView -Title 'Action Required - Connectivity Issues'" -ForegroundColor Green
Write-Host ""
Write-Host "     View all connectivity failures:" -ForegroundColor White
Write-Host "     » `$BlockedResults | Out-GridView" -ForegroundColor Yellow
Write-Host "     » `$BlockedResults | Out-GridView -Title 'Blocked — Actionable Failures'" -ForegroundColor Yellow
Write-Host ""
Write-Host "     View endpoints not resolvable via public DNS (informational — no action needed):" -ForegroundColor White
Write-Host "     » `$UnresolvableHosts | Out-GridView" -ForegroundColor DarkGray
Write-Host ""
Write-Host "     View all critical endpoints:" -ForegroundColor White
Write-Host "     » `$SummaryTable | Where Critical -eq 'YES' | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     View SSL bypass requirements:" -ForegroundColor White
Write-Host "     » `$BasicRequired | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     View endpoints needing unauthenticated proxy access:" -ForegroundColor White
Write-Host "     » `$ProxyRequired | Out-GridView" -ForegroundColor Yellow
Write-Host "     » `$Results | Where Action_Proxy -ne '-' | Out-GridView" -ForegroundColor Yellow
Write-Host "     » `$SummaryTable | Where Action_Proxy -ne '-' | Out-GridView" -ForegroundColor Yellow
Write-Host ""
Write-Host "     Export all data to CSV:" -ForegroundColor White
Write-Host "     » `$Results | Export-Csv Desktop\ConnectivityResults.csv -NoType" -ForegroundColor Yellow
Write-Host "     » `$SummaryTable | Export-Csv Desktop\NetworkRequirements.csv -NoType" -ForegroundColor Yellow
Write-Host "     » `$BasicRequired | Export-Csv Desktop\SSL_Bypass_List.csv -NoType" -ForegroundColor Yellow
Write-Host "     » `$ProxyRequired | Export-Csv Desktop\Proxy_Unauth_List.csv -NoType" -ForegroundColor Yellow
Write-Host "     » `$ActionReport | Export-Csv Desktop\ActionRequired.csv -NoType" -ForegroundColor Yellow
Write-Host ""
Write-Host "     Generate HTML report:" -ForegroundColor White
Write-Host "     » Run script with -ExportHTML flag:" -ForegroundColor DarkGray
Write-Host "       .\connectivity_checker_simplified.ps1 -ExportHTML" -ForegroundColor Cyan
Write-Host "     » Or generate from current session data:" -ForegroundColor DarkGray
Write-Host "       Export-HTMLReport -Path `"`$env:USERPROFILE\Desktop\ConnectivityReport.html`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅ SUMMARY - Copy this for your documentation:" -ForegroundColor Green
Write-Host "  ═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  `$Results       = `"DID IT WORK?`"" -ForegroundColor Cyan
Write-Host "    → DIAGNOSTIC DATA - Shows what happened when testing (ALL endpoints)" -ForegroundColor Gray
Write-Host "    → Contains: DNS resolution, TCP connectivity, TLS handshake, DNS_Public" -ForegroundColor Gray
Write-Host "    → Purpose: Troubleshooting — use `$BlockedResults for actionable failures" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$BlockedResults = `"WHAT IS ACTUALLY BLOCKED?`"" -ForegroundColor Yellow
Write-Host "    → `$Results filtered to actionable failures only" -ForegroundColor Gray
Write-Host "    → Excludes endpoints where DNS_Public = 'Not publicly resolvable'" -ForegroundColor Gray
Write-Host "    → Use this instead of: `$Results | Where Status -ne 'OK'" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$SummaryTable = `"WHAT DO I NEED?`"" -ForegroundColor Cyan
Write-Host "    → CONFIGURATION DATA - Lists what should be allowed in firewall" -ForegroundColor Gray
Write-Host "    → Contains: Unique endpoints (deduplicated), no test results" -ForegroundColor Gray
Write-Host "    → Purpose: Configuring network/firewall rules" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$BasicRequired = `"WHAT MUST BYPASS SSL?`"" -ForegroundColor Magenta
Write-Host "    → CRITICAL SECURITY CONFIG - Endpoints that WILL FAIL if proxied" -ForegroundColor Gray
Write-Host "    → Contains: Endpoints requiring SSL/TLS inspection bypass" -ForegroundColor Gray
Write-Host "    → Purpose: Configuring proxy exclusions / SSL bypass rules" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$ProxyRequired = `"WHAT NEEDS UNAUTHENTICATED PROXY ACCESS?`"" -ForegroundColor DarkYellow
Write-Host "    → PROXY CONFIG DATA - Endpoints needing unauthenticated SYSTEM access" -ForegroundColor Gray
Write-Host "    → Covers: manage.microsoft.com, graph.microsoft.com (+ *.azureedge.net)" -ForegroundColor Gray
Write-Host "    → Purpose: Configure proxy to allow unauthenticated SYSTEM account access" -ForegroundColor Gray
Write-Host ""
Write-Host "  `$UnresolvableHosts = `"NOT RESOLVABLE VIA PUBLIC DNS (informational)`"" -ForegroundColor DarkGray
Write-Host "    → Endpoints with DNS_FAIL that also fail Google DNS (8.8.8.8)" -ForegroundColor Gray
Write-Host "    → These are NOT publicly registered — DNS_FAIL is expected" -ForegroundColor Gray
Write-Host "    → No firewall action required — excluded from CRITICAL/WARN counts" -ForegroundColor Gray
Write-Host ""
Write-Host "  ℹ️  DNS VERIFICATION LOGIC:" -ForegroundColor Cyan
Write-Host "    When an endpoint fails DNS resolution (DNS_FAIL), the script performs" -ForegroundColor Gray
Write-Host "    a secondary check using Google DNS (8.8.8.8) to distinguish:" -ForegroundColor Gray
Write-Host "      • Local DNS cannot resolve           → endpoint IS publicly resolvable (8.8.8.8 resolves it)," -ForegroundColor Gray
Write-Host "                                            but your local DNS cannot resolve it — check DNS" -ForegroundColor Gray
Write-Host "                                            settings, ISP filtering, or corporate DNS policy" -ForegroundColor Gray
Write-Host "      • Not publicly resolvable          → endpoint does NOT exist in public DNS," -ForegroundColor Gray
Write-Host "                                            DNS_FAIL is expected, no action needed" -ForegroundColor Gray
Write-Host "      • External DNS blocked (port 53)   → cannot reach 8.8.8.8:53 to check," -ForegroundColor Gray
Write-Host "                                            treat the DNS_FAIL as potentially real" -ForegroundColor Gray
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# ── Export HTML Report ──
if ($ExportHTML) {
    Export-HTMLReport -Path $HTMLPath
}
else {
    Write-Host "  Tip: Generate a full HTML report with tabbed action guidance:" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "       Run script with -ExportHTML flag:" -ForegroundColor DarkGray
    Write-Host "       .\connectivity_checker_simplified.ps1 -ExportHTML" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "       Or generate from current session data (no re-run needed):" -ForegroundColor DarkGray
    Write-Host "       Export-HTMLReport -Path `"`$env:USERPROFILE\Desktop\ConnectivityReport.html`"" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ↑  SCROLL UP  — key sections to review:" -ForegroundColor Yellow
    Write-Host "     !! ACTION REQUIRED   — endpoints blocked by your network (test result)" -ForegroundColor Red
    Write-Host "     SSL/TLS BYPASS INFO  — endpoints where MS docs require SSL bypass" -ForegroundColor DarkYellow
    Write-Host "                            (configure in firewall/proxy — not a test result)" -ForegroundColor DarkGray
    Write-Host "     PROXY CONFIG INFO    — endpoints where MS docs require unauthenticated" -ForegroundColor DarkYellow
    Write-Host "                            proxy access for SYSTEM account (not a test result)" -ForegroundColor DarkGray
    Write-Host "  ════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  🌐 NETWORK ENVIRONMENT CONTEXT" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ("  DNS Servers     : {0}" -f $NetworkCtx.DNSServers) -ForegroundColor $(if ($NetworkCtx.CorporateDNSLikely) { "Yellow" } else { "Gray" })
    if ($NetworkCtx.CorporateDNSLikely) {
        Write-Host "                    ⚠️  Private/corporate range — DNS filtering may affect results" -ForegroundColor Yellow
        Write-Host "                    DNS_FAIL may reflect local DNS policy — check DNS_Public column" -ForegroundColor DarkYellow
    }
    Write-Host ("  VPN             : {0}" -f $(if ($NetworkCtx.VPNDetected) { "⚠️  DETECTED — $($NetworkCtx.VPNAdapter)" } else { "Not detected" })) -ForegroundColor $(if ($NetworkCtx.VPNDetected) { "Yellow" } else { "Gray" })
    Write-Host ("  Proxy (IE/User) : {0}{1}" -f $(if ($NetworkCtx.ProxyEnabled) { "⚠️  $($NetworkCtx.ProxyServer)" } else { "Not configured" }), $(if ($NetworkCtx.WPADEnabled) { " [WPAD/AutoDetect ON]" } else { "" })) -ForegroundColor $(if ($NetworkCtx.ProxyEnabled) { "Yellow" } else { "Gray" })
    Write-Host ("  Proxy (WinHTTP) : {0}" -f $(if ($NetworkCtx.WinHTTPProxy -ne "-") { "⚠️  $($NetworkCtx.WinHTTPProxy)" } else { "Not configured" })) -ForegroundColor $(if ($NetworkCtx.WinHTTPProxy -ne "-") { "Yellow" } else { "Gray" })
    Write-Host ("  OS TLS (SCHANNEL): {0}" -f $NetworkCtx.DotNetTLS) -ForegroundColor $(if ($NetworkCtx.DotNetTLSWarn) { "Red" } else { "Gray" })
    if ($NetworkCtx.DotNetTLSWarn) {
        Write-Host "                    ⚠️  TLS 1.0/1.1 active or TLS 1.2/1.3 missing — change needed!" -ForegroundColor Red
        Write-Host "                    Disable TLS 1.0/1.1, enable TLS 1.2/1.3 in SCHANNEL registry" -ForegroundColor DarkRed
    }
    Write-Host ("  .NET TLS default (Powershell session) : {0}" -f $NetworkCtx.ServicePointTLS) -ForegroundColor $(if ($NetworkCtx.ServicePointWarn) { "Red" } else { "Gray" })
    if ($NetworkCtx.ServicePointWarn) {
        Write-Host "                    ⚠️  PowerShell/.NET not defaulting to TLS 1.2/1.3!" -ForegroundColor Red
        Write-Host "                    Run: [Net.ServicePointManager]::SecurityProtocol = 'Tls12,Tls13'" -ForegroundColor DarkRed
    }
    Write-Host "  ══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  See QUICK ACTIONS section above for full syntax to generate detailed" -ForegroundColor DarkGray
    Write-Host "  network reports (CSV, HTML, Out-GridView). Quick start:" -ForegroundColor DarkGray
    Write-Host "     `$ActionReport | Out-GridView -Title 'Action Required'" -ForegroundColor Green
    Write-Host "     Export-HTMLReport -Path `"`$env:USERPROFILE\Desktop\ConnectivityReport.html`"" -ForegroundColor Cyan
    Write-Host ""
}

