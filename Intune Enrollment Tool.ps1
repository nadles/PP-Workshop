#Requires -Version 5.1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:AttributeName = 'msDS-cloudExtensionAttribute14'
$script:ValueToAdd     = 'SYNC'
$script:IsRunning     = $false
$script:AppTitle      = 'Intune Enrollment Tool'
$script:AuthorEmail   = 'marcin.nadlewski@promise.pl'
$script:LogDirectory  = Join-Path ($(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })) 'Logs'
$script:SessionLogFile = $null

$script:UiColors = @{
    Accent       = [System.Drawing.Color]::FromArgb(0, 120, 212)
    AccentHover  = [System.Drawing.Color]::FromArgb(16, 110, 190)
    Background   = [System.Drawing.Color]::FromArgb(243, 245, 248)
    Surface      = [System.Drawing.Color]::FromArgb(255, 255, 255)
    Border       = [System.Drawing.Color]::FromArgb(225, 228, 234)
    TextPrimary  = [System.Drawing.Color]::FromArgb(32, 32, 32)
    TextMuted    = [System.Drawing.Color]::FromArgb(96, 104, 118)
    LogBg        = [System.Drawing.Color]::FromArgb(28, 32, 38)
    LogText      = [System.Drawing.Color]::FromArgb(220, 224, 230)
    LogInfo      = [System.Drawing.Color]::FromArgb(125, 200, 255)
}

function New-UiCard {
    param(
        [System.Windows.Forms.Control]$Parent,
        [System.Drawing.Point]$Location,
        [System.Drawing.Size]$Size,
        [System.Windows.Forms.AnchorStyles]$Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
    )

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = $Location
    $panel.Size = $Size
    $panel.Anchor = $Anchor
    $panel.BackColor = $script:UiColors.Surface
    $panel.Padding = New-Object System.Windows.Forms.Padding(16, 14, 16, 14)
    $panel.BorderStyle = 'FixedSingle'
    $Parent.Controls.Add($panel)
    return $panel
}

function New-UiLabel {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Text,
        [System.Drawing.Point]$Location,
        [System.Drawing.Size]$Size,
        [System.Drawing.Font]$Font,
        [System.Drawing.Color]$ForeColor,
        [System.Windows.Forms.AnchorStyles]$Anchor = ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left)
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = $Location
    $label.Size = $Size
    $label.Font = $Font
    $label.ForeColor = $ForeColor
    $label.Anchor = $Anchor
    $label.BackColor = [System.Drawing.Color]::Transparent
    $Parent.Controls.Add($label)
    return $label
}

function New-UiButton {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Text,
        [System.Drawing.Point]$Location,
        [System.Drawing.Size]$Size,
        [switch]$Primary
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = $Location
    $button.Size = $Size
    $button.FlatStyle = 'Flat'
    $button.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand

    if ($Primary) {
        $button.BackColor = $script:UiColors.Accent
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatAppearance.BorderSize = 0
        $button.Add_MouseEnter({ $this.BackColor = $script:UiColors.AccentHover })
        $button.Add_MouseLeave({ $this.BackColor = $script:UiColors.Accent })
    }
    else {
        $button.BackColor = $script:UiColors.Surface
        $button.ForeColor = $script:UiColors.TextPrimary
        $button.FlatAppearance.BorderColor = $script:UiColors.Border
        $button.FlatAppearance.BorderSize = 1
        $button.Add_MouseEnter({ $this.BackColor = $script:UiColors.Background })
        $button.Add_MouseLeave({ $this.BackColor = $script:UiColors.Surface })
    }

    $Parent.Controls.Add($button)
    return $button
}

function Write-Log {
    param(
        [string]$Message,
        [System.Drawing.Color]$Color = $script:UiColors.LogText
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] $Message"

    if ($script:LogBox.InvokeRequired) {
        $script:LogBox.Invoke([Action]{
            param($text, $clr)
            $script:LogBox.SelectionStart = $script:LogBox.TextLength
            $script:LogBox.SelectionLength = 0
            $script:LogBox.SelectionColor = $clr
            $script:LogBox.AppendText("$text`r`n")
            $script:LogBox.SelectionColor = $script:LogBox.ForeColor
            $script:LogBox.ScrollToCaret()
        }, $line, $Color) | Out-Null
    }
    else {
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.SelectionLength = 0
        $script:LogBox.SelectionColor = $Color
        $script:LogBox.AppendText("$line`r`n")
        $script:LogBox.SelectionColor = $script:LogBox.ForeColor
        $script:LogBox.ScrollToCaret()
    }

    [System.Windows.Forms.Application]::DoEvents()
}

function Initialize-SessionLog {
    param([int]$ComputerCount)

    if (-not (Test-Path -LiteralPath $script:LogDirectory)) {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }

    $fileName = '{0}.txt' -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')
    $script:SessionLogFile = Join-Path $script:LogDirectory $fileName

    $header = @(
        '========================================'
        'Intune Enrollment Tool - log sesji'
        "Data rozpoczęcia: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "Użytkownik: $env:USERDOMAIN\$env:USERNAME"
        "Komputerów do przetworzenia: $ComputerCount"
        "Atrybut: $($script:AttributeName)"
        "Wartość: $($script:ValueToAdd)"
        '========================================'
        ''
    ) -join [Environment]::NewLine

    Set-Content -LiteralPath $script:SessionLogFile -Value $header -Encoding UTF8
}

function Write-FileLog {
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($script:SessionLogFile)) { return }

    Add-Content -LiteralPath $script:SessionLogFile -Value $Line -Encoding UTF8
}

function Complete-SessionLog {
    param(
        [int]$SuccessCount,
        [int]$SkippedCount,
        [int]$FailedCount
    )

    $summary = @(
        ''
        '----------------------------------------'
        "Podsumowanie sesji: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "Sukces: $SuccessCount"
        "Pominięte (wartość już istnieje): $SkippedCount"
        "Błąd: $FailedCount"
        '========================================'
    ) -join [Environment]::NewLine

    Write-FileLog -Line $summary
}

function Get-ComputerList {
    $raw = $script:ComputerBox.Lines
    $list = @()

    foreach ($line in $raw) {
        $name = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        foreach ($part in ($name -split '[,;]')) {
            $part = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($part)) {
                $list += $part
            }
        }
    }

    return ($list | Select-Object -Unique)
}

function Update-ComputerAttribute {
    param([string]$ComputerName)

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    try {
        $adComputer = Get-ADComputer -Filter "Name -eq '$($ComputerName.Replace("'", "''"))'" -Properties $script:AttributeName -ErrorAction Stop

        $currentValues = @()
        if ($null -ne $adComputer.$script:AttributeName) {
            $currentValues = @($adComputer.$script:AttributeName)
        }

        if ($currentValues -contains $script:ValueToAdd) {
            $details = "Wartość '$($script:ValueToAdd)' już istnieje w atrybucie $($script:AttributeName). Brak zmian."
            Write-Log -Message "$ComputerName - $details" -Color ([System.Drawing.Color]::DarkGoldenrod)
            Write-FileLog -Line "[$timestamp] $ComputerName | POMINIĘTY | $details"
            return 'Skipped'
        }

        $before = if ($currentValues.Count -gt 0) { ($currentValues -join ', ') } else { '(pusty)' }

        Set-ADComputer -Identity $adComputer -Add @{ $script:AttributeName = $script:ValueToAdd } -ErrorAction Stop

        $afterValues = @($currentValues) + $script:ValueToAdd
        $after = $afterValues -join ', '

        $details = "Dodano '$($script:ValueToAdd)' do $($script:AttributeName). Przed: [$before] -> Po: [$after]"
        Write-Log -Message "$ComputerName - $details" -Color ([System.Drawing.Color]::DarkGreen)
        Write-FileLog -Line "[$timestamp] $ComputerName | SUKCES | $details"
        return 'Success'
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $details = 'Nie znaleziono obiektu komputera w Active Directory.'
        Write-Log -Message "$ComputerName - $details" -Color ([System.Drawing.Color]::Red)
        Write-FileLog -Line "[$timestamp] $ComputerName | BŁĄD | $details"
        return 'Failed'
    }
    catch {
        $details = $_.Exception.Message
        Write-Log -Message "$ComputerName - błąd: $details" -Color ([System.Drawing.Color]::Red)
        Write-FileLog -Line "[$timestamp] $ComputerName | BŁĄD | $details"
        return 'Failed'
    }
}

function Start-Processing {
    if ($script:IsRunning) { return }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        [System.Windows.Forms.MessageBox]::Show(
            'Moduł ActiveDirectory nie jest dostępny. Zainstaluj narzędzia RSAT (Active Directory module for Windows PowerShell).',
            $script:AppTitle,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Wprowadź co najmniej jedną nazwę komputera (jedna nazwa w wierszu).',
            $script:AppTitle,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    $script:IsRunning = $true
    $script:StartButton.Enabled = $false
    $script:ComputerBox.ReadOnly = $true

    Initialize-SessionLog -ComputerCount $computers.Count

    Write-Log -Message "Rozpoczęto przetwarzanie $($computers.Count) komputerów..." -Color $script:UiColors.LogInfo
    Write-Log -Message "Log sesji: $script:SessionLogFile" -Color ([System.Drawing.Color]::Gray)

    $successCount = 0
    $skippedCount = 0
    $failedCount = 0

    foreach ($computer in $computers) {
        switch (Update-ComputerAttribute -ComputerName $computer) {
            'Success' { $successCount++ }
            'Skipped' { $skippedCount++ }
            'Failed'  { $failedCount++ }
        }
    }

    Complete-SessionLog -SuccessCount $successCount -SkippedCount $skippedCount -FailedCount $failedCount

    Write-Log -Message "Zakończono przetwarzanie. Sukces: $successCount | Pominięte: $skippedCount | Błąd: $failedCount" -Color $script:UiColors.LogInfo

    $script:IsRunning = $false
    $script:StartButton.Enabled = $true
    $script:ComputerBox.ReadOnly = $false
}

# --- GUI ---
# Kolejnosc Dock: najpierw Fill, potem Bottom, na koncu Top (inaczej naglowek zaslania tresc).

$form = New-Object System.Windows.Forms.Form
$form.Text = $script:AppTitle
$form.Size = New-Object System.Drawing.Size(860, 700)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(720, 560)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.BackColor = $script:UiColors.Background
$form.Padding = New-Object System.Windows.Forms.Padding(0)

$contentPanel = New-Object System.Windows.Forms.Panel
$contentPanel.Dock = 'Fill'
$contentPanel.Padding = New-Object System.Windows.Forms.Padding(20, 18, 20, 12)
$contentPanel.BackColor = $script:UiColors.Background
$form.Controls.Add($contentPanel)

$footerPanel = New-Object System.Windows.Forms.Panel
$footerPanel.Dock = 'Bottom'
$footerPanel.Height = 34
$footerPanel.BackColor = $script:UiColors.Surface
$footerPanel.Padding = New-Object System.Windows.Forms.Padding(20, 0, 20, 0)
$form.Controls.Add($footerPanel)

$footerSeparator = New-Object System.Windows.Forms.Panel
$footerSeparator.Dock = 'Top'
$footerSeparator.Height = 1
$footerSeparator.BackColor = $script:UiColors.Border
$footerPanel.Controls.Add($footerSeparator)

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = 'Top'
$headerPanel.Height = 88
$headerPanel.BackColor = $script:UiColors.Accent
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = $script:AppTitle
$titleLabel.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 16)
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titleLabel.Location = New-Object System.Drawing.Point(24, 18)
$titleLabel.Size = New-Object System.Drawing.Size(520, 34)
$titleLabel.BackColor = [System.Drawing.Color]::Transparent
$headerPanel.Controls.Add($titleLabel)

$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "Ustawianie atrybutu $($script:AttributeName) = $($script:ValueToAdd)"
$subtitleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$subtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(220, 235, 250)
$subtitleLabel.Location = New-Object System.Drawing.Point(26, 52)
$subtitleLabel.Size = New-Object System.Drawing.Size(520, 22)
$subtitleLabel.BackColor = [System.Drawing.Color]::Transparent
$headerPanel.Controls.Add($subtitleLabel)

$authorLabel = New-Object System.Windows.Forms.Label
$authorLabel.Text = $script:AuthorEmail
$authorLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$authorLabel.ForeColor = [System.Drawing.Color]::FromArgb(210, 228, 248)
$authorLabel.AutoSize = $true
$authorLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$authorLabel.BackColor = [System.Drawing.Color]::Transparent
$headerPanel.Controls.Add($authorLabel)

$computersCard = New-UiCard -Parent $contentPanel -Location (New-Object System.Drawing.Point($contentPanel.Padding.Left, $contentPanel.Padding.Top)) -Size (New-Object System.Drawing.Size(800, 250)) -Anchor ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)
$computersCard.Height = 250

$null = New-UiLabel -Parent $computersCard -Text 'Komputery do przetworzenia' -Location (New-Object System.Drawing.Point(16, 14)) -Size (New-Object System.Drawing.Size(400, 24)) -Font (New-Object System.Drawing.Font('Segoe UI Semibold', 10.5)) -ForeColor $script:UiColors.TextPrimary
$null = New-UiLabel -Parent $computersCard -Text 'Wprowadź nazwy komputerów — jedna nazwa w wierszu.' -Location (New-Object System.Drawing.Point(16, 38)) -Size (New-Object System.Drawing.Size(500, 20)) -Font (New-Object System.Drawing.Font('Segoe UI', 9)) -ForeColor $script:UiColors.TextMuted

$script:ComputerBox = New-Object System.Windows.Forms.TextBox
$script:ComputerBox.Multiline = $true
$script:ComputerBox.ScrollBars = 'Vertical'
$script:ComputerBox.Location = New-Object System.Drawing.Point(16, 64)
$script:ComputerBox.Size = New-Object System.Drawing.Size(768, 130)
$script:ComputerBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
$script:ComputerBox.AcceptsReturn = $true
$script:ComputerBox.BorderStyle = 'FixedSingle'
$script:ComputerBox.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$script:ComputerBox.BackColor = [System.Drawing.Color]::FromArgb(250, 251, 253)
$computersCard.Controls.Add($script:ComputerBox)

$actionsPanel = New-Object System.Windows.Forms.Panel
$actionsPanel.Location = New-Object System.Drawing.Point($contentPanel.Padding.Left, 262)
$actionsPanel.Size = New-Object System.Drawing.Size(800, 44)
$actionsPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$actionsPanel.BackColor = [System.Drawing.Color]::Transparent
$contentPanel.Controls.Add($actionsPanel)

$script:StartButton = New-UiButton -Parent $actionsPanel -Text 'START' -Location (New-Object System.Drawing.Point(0, 4)) -Size (New-Object System.Drawing.Size(140, 36)) -Primary
$script:StartButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$script:StartButton.Add_Click({ Start-Processing })

$clearLogButton = New-UiButton -Parent $actionsPanel -Text 'Wyczyść log' -Location (New-Object System.Drawing.Point(660, 4)) -Size (New-Object System.Drawing.Size(140, 36))
$clearLogButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$clearLogButton.Add_Click({ $script:LogBox.Clear() })

$logCard = New-UiCard -Parent $contentPanel -Location (New-Object System.Drawing.Point($contentPanel.Padding.Left, 316)) -Size (New-Object System.Drawing.Size(800, 280)) -Anchor ([System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right)

$null = New-UiLabel -Parent $logCard -Text 'Log operacji' -Location (New-Object System.Drawing.Point(16, 14)) -Size (New-Object System.Drawing.Size(200, 24)) -Font (New-Object System.Drawing.Font('Segoe UI Semibold', 10.5)) -ForeColor $script:UiColors.TextPrimary

$script:LogBox = New-Object System.Windows.Forms.RichTextBox
$script:LogBox.ReadOnly = $true
$script:LogBox.Location = New-Object System.Drawing.Point(16, 44)
$script:LogBox.Size = New-Object System.Drawing.Size(768, 210)
$script:LogBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$script:LogBox.BackColor = $script:UiColors.LogBg
$script:LogBox.ForeColor = $script:UiColors.LogText
$script:LogBox.BorderStyle = 'None'
$script:LogBox.Font = New-Object System.Drawing.Font('Cascadia Mono', 9.5, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Point)
if (-not $script:LogBox.Font.Name.Contains('Cascadia')) {
    $script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9.5)
}
$logCard.Controls.Add($script:LogBox)

$footerAuthor = New-Object System.Windows.Forms.Label
$footerAuthor.Text = "Autor: $($script:AuthorEmail)"
$footerAuthor.Dock = 'Left'
$footerAuthor.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$footerAuthor.ForeColor = $script:UiColors.TextMuted
$footerAuthor.Font = New-Object System.Drawing.Font('Segoe UI', 8.75)
$footerAuthor.BackColor = [System.Drawing.Color]::Transparent
$footerPanel.Controls.Add($footerAuthor)

$footerInfo = New-Object System.Windows.Forms.Label
$footerInfo.Text = "$($script:AttributeName) | wartość: $($script:ValueToAdd)"
$footerInfo.Dock = 'Right'
$footerInfo.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$footerInfo.ForeColor = $script:UiColors.TextMuted
$footerInfo.Font = New-Object System.Drawing.Font('Segoe UI', 8.75)
$footerInfo.AutoSize = $true
$footerInfo.BackColor = [System.Drawing.Color]::Transparent
$footerPanel.Controls.Add($footerInfo)

$contentPanel.Add_Resize({
    $padLeft = $contentPanel.Padding.Left
    $padTop = $contentPanel.Padding.Top
    $padBottom = $contentPanel.Padding.Bottom
    $innerWidth = [Math]::Max(400, $contentPanel.ClientSize.Width - $contentPanel.Padding.Left - $contentPanel.Padding.Right)
    $sectionGap = 12

    $computersCard.Left = $padLeft
    $computersCard.Top = $padTop
    $computersCard.Width = $innerWidth

    $actionsPanel.Left = $padLeft
    $actionsPanel.Width = $innerWidth
    $actionsPanel.Top = $computersCard.Bottom + $sectionGap

    $logCard.Left = $padLeft
    $logCard.Width = $innerWidth
    $logCard.Top = $actionsPanel.Bottom + $sectionGap
    $logCard.Height = [Math]::Max(180, $contentPanel.ClientSize.Height - $logCard.Top - $padBottom)
})

$form.Add_Load({
    $authorLabel.Location = New-Object System.Drawing.Point(($headerPanel.Width - $authorLabel.Width - 24), 30)
    $contentPanel.PerformLayout()
})

$headerPanel.Add_Resize({
    $authorLabel.Location = New-Object System.Drawing.Point(($headerPanel.Width - $authorLabel.Width - 24), 30)
})

Write-Log -Message 'Gotowy. Wprowadź nazwy komputerów i kliknij START.' -Color ([System.Drawing.Color]::FromArgb(150, 156, 168))

[void]$form.ShowDialog()
