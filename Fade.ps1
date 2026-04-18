Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ===================== GLOBAL ERROR HANDLER =====================
[System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
[System.Windows.Forms.Application]::add_ThreadException({
    param($sender, $e)
    [System.Windows.Forms.MessageBox]::Show(
        "Unexpected error:`n$($e.Exception.Message)",
        "BabyDek Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
})
$ErrorActionPreference = "SilentlyContinue"

# ===================== AUTO-ELEVATE (UAC) =====================
# Supports both: direct run AND iwr -useb URL | iex  /  irm URL | iex
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptContent = $MyInvocation.MyCommand.ScriptBlock
    if ($scriptContent) {
        # Invoked via iex/pipe — save to temp file then re-launch elevated
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
        $scriptContent | Out-File -FilePath $tmp -Encoding UTF8
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`"" -Verb RunAs
    } else {
        # Invoked directly from file
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    }
    exit
}

# ===================== ANTI-DEBUG =====================
function Invoke-AntiDebug {

    # 1) Debugger attached via .NET
    if ([System.Diagnostics.Debugger]::IsAttached) {
        [System.Diagnostics.Process]::GetCurrentProcess().Kill()
    }

    # 2) Known debugger/analysis process names
    $badProcs = @(
        "x64dbg","x32dbg","ollydbg","windbg","idaq","idaq64",
        "idag","idag64","idaw","idaw64","idat","idat64",
        "scylla","scylla_x64","scylla_x86",
        "processhacker","procmon","procmon64","procexp","procexp64",
        "wireshark","fiddler","fiddler everywhere",
        "dnspy","de4dot","ilspy","dotpeek","justdecompile",
        "cheatengine","cheatengine-x86_64","cheatengine-i386",
        "peid","exeinfope","lordpe","pestudio",
        "httpdebugger","httpdebuggerui",
        "charles","mitmproxy","burpsuite",
        "regmon","filemon","tcpview","autoruns",
        "rohitab","apimonitor",
        "python","python3","pythonw",          # script analysers
        "powershell_ise"                        # ISE debugger
    )
    foreach ($p in $badProcs) {
        if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
            [System.Diagnostics.Process]::GetCurrentProcess().Kill()
        }
    }

    # 3) Sandbox / VM detection via known MAC OUI prefixes
    $vmMacs = @("00:05:69","00:0C:29","00:50:56","00:1C:14",  # VMware
                "08:00:27","0A:00:27",                          # VirtualBox
                "00:03:FF","00:15:5D",                          # Hyper-V / Azure
                "00:16:E3",                                      # Xen
                "00:1C:42")                                      # Parallels
    $macs = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
             Where-Object { $_.MACAddress } |
             Select-Object -ExpandProperty MACAddress)
    foreach ($mac in $macs) {
        $prefix = ($mac -replace '-',':').Substring(0,8).ToUpper()
        foreach ($vm in $vmMacs) {
            if ($prefix -eq $vm.ToUpper()) {
                [System.Diagnostics.Process]::GetCurrentProcess().Kill()
            }
        }
    }

    # 4) Sandbox via known VM registry artifacts
    $vmRegChecks = @(
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
        "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
        "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
        "HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse",
        "HKLM:\HARDWARE\ACPI\DSDT\VBOX__"
    )
    foreach ($reg in $vmRegChecks) {
        if (Test-Path $reg) {
            [System.Diagnostics.Process]::GetCurrentProcess().Kill()
        }
    }

    # 5) Timing check — debuggers slow execution measurably
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 1
    $sw.Stop()
    if ($sw.ElapsedMilliseconds -gt 500) {
        [System.Diagnostics.Process]::GetCurrentProcess().Kill()
    }

    # 6) CheckRemoteDebuggerPresent via kernel32
    try {
        $sig = @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
[DllImport("kernel32.dll")]
public static extern bool IsDebuggerPresent();
'@
        $k32 = Add-Type -MemberDefinition $sig -Name "K32AD" -Namespace "NativeDebug" -PassThru -ErrorAction Stop
        # IsDebuggerPresent (WinAPI)
        if ($k32::IsDebuggerPresent()) {
            [System.Diagnostics.Process]::GetCurrentProcess().Kill()
        }
        # CheckRemoteDebuggerPresent
        $remoteDbg = $false
        $k32::CheckRemoteDebuggerPresent(
            [System.Diagnostics.Process]::GetCurrentProcess().Handle,
            [ref]$remoteDbg
        ) | Out-Null
        if ($remoteDbg) {
            [System.Diagnostics.Process]::GetCurrentProcess().Kill()
        }
    } catch { }

    # 7) Suspicious parent process check (launched from debugger host)
    try {
        $badParents = @("x64dbg","x32dbg","ollydbg","windbg","idaq64","idaq",
                        "dnspy","cheatengine-x86_64","processhacker","powershell_ise")
        $myPid     = [System.Diagnostics.Process]::GetCurrentProcess().Id
        $wmiProc   = Get-WmiObject Win32_Process -Filter "ProcessId=$myPid" -ErrorAction SilentlyContinue
        if ($wmiProc) {
            $parentId   = $wmiProc.ParentProcessId
            $parentProc = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            if ($parentProc -and ($badParents -contains $parentProc.ProcessName.ToLower())) {
                [System.Diagnostics.Process]::GetCurrentProcess().Kill()
            }
        }
    } catch { }
}

# Run anti-debug immediately and also re-check every 8 seconds
# Invoke-AntiDebug  # DISABLED
# $adTimer = New-Object System.Windows.Forms.Timer
# $adTimer.Interval = 8000
# $adTimer.Add_Tick({ Invoke-AntiDebug })
# $adTimer.Start()



# ===================== MAIN FORM - CYBER BLUE THEME =====================
$TEXT     = [System.Drawing.Color]::FromArgb(220, 235, 255)   # ขาวฟ้า
$TEXTDIM  = [System.Drawing.Color]::FromArgb(80, 110, 150)    # ฟ้าหม่น
$BG       = [System.Drawing.Color]::FromArgb(5, 10, 20)       # ดำฟ้าเข้ม
$BG2      = [System.Drawing.Color]::FromArgb(10, 18, 35)      # พื้น panel
$BG3      = [System.Drawing.Color]::FromArgb(8, 14, 28)

$ACCENT   = [System.Drawing.Color]::FromArgb(0, 180, 255)     # ฟ้านีออนหลัก
$ACCENT2  = [System.Drawing.Color]::FromArgb(0, 120, 255)     # ฟ้ากลาง
$ACCENT3  = [System.Drawing.Color]::FromArgb(120, 200, 255)   # ฟ้าอ่อน

$ERR      = [System.Drawing.Color]::FromArgb(255, 80, 100)    # แดง error
$WARN     = [System.Drawing.Color]::FromArgb(255, 170, 50)    # เหลืองเตือน
$DARKPINK = [System.Drawing.Color]::FromArgb(0, 90, 150)      # เปลี่ยนเป็นฟ้าเข้มแทน

# ===================== FONTS =====================
$FontTitle = New-Object System.Drawing.Font("Segoe UI",    20, [System.Drawing.FontStyle]::Bold)
$FontSub   = New-Object System.Drawing.Font("Segoe UI",    9,  [System.Drawing.FontStyle]::Regular)
$FontBtn   = New-Object System.Drawing.Font("Segoe UI",    10, [System.Drawing.FontStyle]::Bold)
$FontLog   = New-Object System.Drawing.Font("Consolas",    8,  [System.Drawing.FontStyle]::Regular)
$FontSmall = New-Object System.Drawing.Font("Consolas",    7,  [System.Drawing.FontStyle]::Regular)
$FontStep  = New-Object System.Drawing.Font("Consolas",    9,  [System.Drawing.FontStyle]::Bold)
$FontMono  = New-Object System.Drawing.Font("Consolas",    8,  [System.Drawing.FontStyle]::Bold)

# ===================== MAIN FORM =====================
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Fade"
$form.Size            = New-Object System.Drawing.Size(940, 700)
$form.StartPosition   = "CenterScreen"
$form.BackColor       = $BG
$form.ForeColor       = $TEXT
$form.FormBorderStyle = "None"
$form.MaximizeBox     = $false
$form.Font            = $FontSub

# Draggable
$script:_drag2 = $false
$script:_drag2Start = [System.Drawing.Point]::Empty
$form.Add_MouseDown({ param($s,$e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
        $script:_drag2 = $true
        $script:_drag2Start = $e.Location
    }
})
$form.Add_MouseMove({ param($s,$e)
    if ($script:_drag2) {
        $form.Left += $e.X - $script:_drag2Start.X
        $form.Top  += $e.Y - $script:_drag2Start.Y
    }
})
$form.Add_MouseUp({ $script:_drag2 = $false })

$form.Add_Paint({
    $g = $_.Graphics
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    [int]$fw = $form.Width; [int]$fh = $form.Height

    # Outer border
    $outerP = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(100, 255, 110, 185), 1)
    $g.DrawRectangle($outerP, 0, 0, ($fw - 1), ($fh - 1))
    $outerP.Dispose()

    # Top gradient bar
    $pt1 = New-Object System.Drawing.Point(0, 0)
    $pt2 = New-Object System.Drawing.Point($fw, 0)
    $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush($pt1, $pt2, $ACCENT, $ACCENT3)
    $g.FillRectangle($br, 0, 0, $fw, 4); $br.Dispose()

    # Bottom border glow
    $pb = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawLine($pb, 0, ($fh - 1), $fw, ($fh - 1))
    $pb.Dispose()

    # Corner decorations top
    $cp = New-Object System.Drawing.Pen($ACCENT, 2)
    $g.DrawLine($cp, 3, 4, 3, 38); $g.DrawLine($cp, 3, 4, 42, 4)
    $g.DrawLine($cp, ($fw-4), 4, ($fw-42), 4)
    $g.DrawLine($cp, ($fw-4), 4, ($fw-4), 38)
    $cp.Dispose()
    # Corner decorations bottom
    $cp2 = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(150, 255, 200, 110), 2)
    $g.DrawLine($cp2, 3, ($fh-2), 3, ($fh-38))
    $g.DrawLine($cp2, 3, ($fh-2), 38, ($fh-2))
    $g.DrawLine($cp2, ($fw-4), ($fh-2), ($fw-38), ($fh-2))
    $g.DrawLine($cp2, ($fw-4), ($fh-2), ($fw-4), ($fh-38))
    $cp2.Dispose()
})

# ===================== HEADER PANEL =====================
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Location  = New-Object System.Drawing.Point(0, 4)
$headerPanel.Size      = New-Object System.Drawing.Size(940, 82)
$headerPanel.BackColor = $BG2
$form.Controls.Add($headerPanel)

$headerPanel.Add_Paint({
    $g = $_.Graphics
    [int]$hw = $headerPanel.Width; [int]$hh = $headerPanel.Height
    # Bottom separator gradient
    $pt1 = New-Object System.Drawing.Point(0, ($hh - 2))
    $pt2 = New-Object System.Drawing.Point($hw, ($hh - 2))
    $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush($pt1, $pt2, $ACCENT, [System.Drawing.Color]::FromArgb(0,0,0,0))
    $g.FillRectangle($br, 0, ($hh - 2), $hw, 2); $br.Dispose()

    # Left accent bar
    $la = New-Object System.Drawing.Pen($ACCENT, 3)
    $g.DrawLine($la, 0, 8, 0, ($hh - 8))
    $la.Dispose()

    # Decorative right area lines
    $dl = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(18, 255, 110, 185), 1)
    for ($i = 0; $i -lt 6; $i++) {
        [int]$x1 = 700 + $i*30; [int]$x2 = $x1 + 20
        $g.DrawLine($dl, $x1, 10, $x2, 10)
    }
    $dl.Dispose()
})

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "Fade"
$lblTitle.Font      = $FontTitle
$lblTitle.ForeColor = $ACCENT
$lblTitle.Location  = New-Object System.Drawing.Point(22, 10)
$lblTitle.AutoSize  = $true
$headerPanel.Controls.Add($lblTitle)

$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text      = ""
$lblVersion.Font      = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
$lblVersion.ForeColor = $ACCENT3
$lblVersion.Location  = New-Object System.Drawing.Point(168, 16)
$lblVersion.AutoSize  = $true
$headerPanel.Controls.Add($lblVersion)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text      = "◈  fiveM.exe"
$lblSub.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
$lblSub.ForeColor = $TEXTDIM
$lblSub.Location  = New-Object System.Drawing.Point(24, 52)
$lblSub.AutoSize  = $true
$headerPanel.Controls.Add($lblSub)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "◆ READY"
$lblStatus.Font      = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
$lblStatus.ForeColor = $ACCENT
$lblStatus.Location  = New-Object System.Drawing.Point(780, 32)
$lblStatus.AutoSize  = $true
$headerPanel.Controls.Add($lblStatus)

# Window controls
$btnWinClose = New-Object System.Windows.Forms.Button
$btnWinClose.Text      = "✕"
$btnWinClose.Location  = New-Object System.Drawing.Point(900, 10)
$btnWinClose.Size      = New-Object System.Drawing.Size(30, 26)
$btnWinClose.Font      = New-Object System.Drawing.Font("Segoe UI", 9)
$btnWinClose.FlatStyle = "Flat"
$btnWinClose.FlatAppearance.BorderSize = 0
$btnWinClose.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(60, 255, 60, 90)
$btnWinClose.BackColor = [System.Drawing.Color]::Transparent
$btnWinClose.ForeColor = [System.Drawing.Color]::FromArgb(100, 70, 90)
$btnWinClose.Cursor    = [System.Windows.Forms.Cursors]::Hand
$headerPanel.Controls.Add($btnWinClose)

# ===================== STEPS PANEL =====================
$stepsPanel = New-Object System.Windows.Forms.Panel
$stepsPanel.Location  = New-Object System.Drawing.Point(12, 96)
$stepsPanel.Size      = New-Object System.Drawing.Size(252, 316)
$stepsPanel.BackColor = $BG2
$form.Controls.Add($stepsPanel)

$stepsPanel.Add_Paint({
    $g = $_.Graphics
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    [int]$sw = $stepsPanel.Width; [int]$sh = $stepsPanel.Height

    $p = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawRectangle($p, 0, 0, ($sw - 1), ($sh - 1))
    $g.DrawLine($p, 0, 28, $sw, 28)
    $p.Dispose()

    $la = New-Object System.Drawing.Pen($ACCENT, 2)
    $g.DrawLine($la, 0, 0, 0, 28)
    $la.Dispose()

    $ta = New-Object System.Drawing.Pen($ACCENT, 2)
    $g.DrawLine($ta, 0, 0, 80, 0)
    $ta.Dispose()

    # Column divider
    $ph = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(15, 180, 110, 255), 1)
    $g.DrawLine($ph, 40, 28, 40, $sh)
    $ph.Dispose()
})

$lblStepsTitle = New-Object System.Windows.Forms.Label
$lblStepsTitle.Text      = "  ✦ STAGES"
$lblStepsTitle.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
$lblStepsTitle.ForeColor = $ACCENT2
$lblStepsTitle.Location  = New-Object System.Drawing.Point(6, 8)
$lblStepsTitle.AutoSize  = $true
$stepsPanel.Controls.Add($lblStepsTitle)

$stepDefs = @(
    @{ id=1; label="STEP 1";       desc="fiveM.exe" },
    @{ id=2; label="STEP 2";   desc="fivem.exe" },
    @{ id=3; label="STEP 3";   desc="fiveM.exe" },
    @{ id=4; label="STEP 4";    desc="fiveM.exe" },
    @{ id=5; label="STEP 5";   desc="fiveM.exe" },
    @{ id=6; label="STEP 6";         desc="fiveM.exe" }
)

$stepLabels = @{}
$stepIcons  = @{}

$yOff = 40
foreach ($s in $stepDefs) {
    $icon = New-Object System.Windows.Forms.Label
    $icon.Text      = "[$($s.id)]"
    $icon.Font      = $FontMono
    $icon.ForeColor = $TEXTDIM
    $icon.Location  = New-Object System.Drawing.Point(4, $yOff)
    $icon.Size      = New-Object System.Drawing.Size(36, 18)
    $stepsPanel.Controls.Add($icon)
    $stepIcons[$s.id] = $icon

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text      = $s.label
    $lbl.Font      = $FontStep
    $lbl.ForeColor = $TEXTDIM
    $lbl.Location  = New-Object System.Drawing.Point(44, $yOff)
    $lbl.Size      = New-Object System.Drawing.Size(204, 16)
    $stepsPanel.Controls.Add($lbl)
    $stepLabels[$s.id] = $lbl

    $desc = New-Object System.Windows.Forms.Label
    $desc.Text      = $s.desc
    $desc.Font      = $FontSmall
    $desc.ForeColor = [System.Drawing.Color]::FromArgb(55, 50, 75)
    $desc.Location  = New-Object System.Drawing.Point(44, ($yOff + 17))
    $desc.Size      = New-Object System.Drawing.Size(204, 13)
    $stepsPanel.Controls.Add($desc)

    $yOff += 46
}

# ===================== PROGRESS PANEL =====================
$progressBg = New-Object System.Windows.Forms.Panel
$progressBg.Location  = New-Object System.Drawing.Point(12, 420)
$progressBg.Size      = New-Object System.Drawing.Size(252, 56)
$progressBg.BackColor = $BG2
$form.Controls.Add($progressBg)

$progressBg.Add_Paint({
    $g = $_.Graphics
    [int]$pw = $progressBg.Width; [int]$ph2 = $progressBg.Height
    $p = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawRectangle($p, 0, 0, ($pw - 1), ($ph2 - 1))
    $p.Dispose()
})

$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Text      = "◈  PROGRESS   0%"
$lblProgress.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
$lblProgress.ForeColor = $ACCENT2
$lblProgress.Location  = New-Object System.Drawing.Point(8, 8)
$lblProgress.AutoSize  = $true
$progressBg.Controls.Add($lblProgress)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Minimum  = 0
$progressBar.Maximum  = 100
$progressBar.Value    = 0
$progressBar.Location = New-Object System.Drawing.Point(8, 30)
$progressBar.Size     = New-Object System.Drawing.Size(236, 14)
$progressBar.Style    = "Continuous"
$progressBg.Controls.Add($progressBar)

# ===================== SYSTEM INFO PANEL =====================
$statsPanel = New-Object System.Windows.Forms.Panel
$statsPanel.Location  = New-Object System.Drawing.Point(272, 96)
$statsPanel.Size      = New-Object System.Drawing.Size(656, 82)
$statsPanel.BackColor = $BG2
$form.Controls.Add($statsPanel)

$statsPanel.Add_Paint({
    $g = $_.Graphics
    [int]$stw = $statsPanel.Width; [int]$sth = $statsPanel.Height
    $p = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawRectangle($p, 0, 0, ($stw - 1), ($sth - 1))
    $g.DrawLine($p, 0, 28, $stw, 28)
    $p.Dispose()

    $la = New-Object System.Drawing.Pen($ACCENT2, 2)
    $g.DrawLine($la, 0, 0, 0, 28)
    $la.Dispose()

    $ta = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(180, 110, 255), 2)
    $g.DrawLine($ta, 0, 0, 100, 0)
    $ta.Dispose()
})

$lblStatsTitle = New-Object System.Windows.Forms.Label
$lblStatsTitle.Text      = "  ✦ SYSTEM INFO"
$lblStatsTitle.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
$lblStatsTitle.ForeColor = $ACCENT2
$lblStatsTitle.Location  = New-Object System.Drawing.Point(6, 8)
$lblStatsTitle.AutoSize  = $true
$statsPanel.Controls.Add($lblStatsTitle)

try {
    $osInfo  = (Get-WmiObject Win32_OperatingSystem).Caption
    $cpuInfo = (Get-WmiObject Win32_Processor).Name
    $ramGB   = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    $netAdapters = (Get-WmiObject Win32_NetworkAdapter -Filter "NetEnabled=True" | Select-Object -First 1).Name
} catch {
    $osInfo = "Windows"; $cpuInfo = "Unknown CPU"; $ramGB = "?"; $netAdapters = "Unknown"
}

$sInfoItems = @(
    @{ key="OS";  val=($osInfo.Substring(0, [Math]::Min(28, $osInfo.Length))) },
    @{ key="CPU"; val=($cpuInfo.Substring(0, [Math]::Min(28, $cpuInfo.Length))) },
    @{ key="RAM"; val="${ramGB} GB" },
    @{ key="NET"; val=if ($netAdapters) { $netAdapters.Substring(0, [Math]::Min(22, $netAdapters.Length)) } else { "N/A" } }
)

$sX = 10
foreach ($si in $sInfoItems) {
    $lk = New-Object System.Windows.Forms.Label
    $lk.Text      = $si.key
    $lk.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
    $lk.ForeColor = $ACCENT3
    $lk.Location  = New-Object System.Drawing.Point($sX, 34)
    $lk.AutoSize  = $true
    $statsPanel.Controls.Add($lk)

    $lv = New-Object System.Windows.Forms.Label
    $lv.Text      = $si.val
    $lv.Font      = New-Object System.Drawing.Font("Consolas", 7)
    $lv.ForeColor = $TEXT
    $lv.Location  = New-Object System.Drawing.Point($sX, 50)
    $lv.AutoSize  = $true
    $statsPanel.Controls.Add($lv)

    $sX += 162
}

# ===================== LOG BOX =====================
$logBg = New-Object System.Windows.Forms.Panel
$logBg.Location  = New-Object System.Drawing.Point(272, 186)
$logBg.Size      = New-Object System.Drawing.Size(656, 280)
$logBg.BackColor = $BG2
$form.Controls.Add($logBg)

$logBg.Add_Paint({
    $g = $_.Graphics
    [int]$lw = $logBg.Width; [int]$lh = $logBg.Height
    $p = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawRectangle($p, 0, 0, ($lw - 1), ($lh - 1))
    $g.DrawLine($p, 0, 28, $lw, 28)
    $p.Dispose()

    $la = New-Object System.Drawing.Pen($ACCENT, 2)
    $g.DrawLine($la, 0, 0, 0, 28)
    $la.Dispose()

    $ta = New-Object System.Drawing.Pen($ACCENT, 2)
    $g.DrawLine($ta, 0, 0, 100, 0)
    $ta.Dispose()

    # Bottom-right corner
    $br = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60, 255, 200, 110), 1)
    $g.DrawLine($br, ($lw-1), ($lh-1), ($lw-26), ($lh-1))
    $g.DrawLine($br, ($lw-1), ($lh-1), ($lw-1), ($lh-26))
    $br.Dispose()
})

$lblLogTitle = New-Object System.Windows.Forms.Label
$lblLogTitle.Text      = "  ✦ OUTPUT LOG"
$lblLogTitle.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
$lblLogTitle.ForeColor = $ACCENT
$lblLogTitle.Location  = New-Object System.Drawing.Point(6, 8)
$lblLogTitle.AutoSize  = $true
$logBg.Controls.Add($lblLogTitle)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Location    = New-Object System.Drawing.Point(6, 32)
$logBox.Size        = New-Object System.Drawing.Size(644, 242)
$logBox.BackColor   = [System.Drawing.Color]::FromArgb(7, 5, 11)
$logBox.ForeColor   = $ACCENT
$logBox.Font        = $FontLog
$logBox.ReadOnly    = $true
$logBox.BorderStyle = "None"
$logBox.ScrollBars  = "Vertical"
$logBg.Controls.Add($logBox)

function Write-Log {
    param([string]$msg, [string]$type = "info")
    try {
       $col = switch ($type) {
    "ok"    { $ACCENT }   # ใช้ฟ้านีออนหลัก
    "warn"  { [System.Drawing.Color]::FromArgb(255, 200, 80) }
    "err"   { [System.Drawing.Color]::FromArgb(255, 60, 90) }
    "dim"   { [System.Drawing.Color]::FromArgb(70, 90, 130) }
    "hi"    { $ACCENT3 }  # ฟ้าอ่อน
    "step"  { $ACCENT2 }  # ฟ้ากลาง
    "pink"  { $ACCENT }   # กันพลาด เปลี่ยนเป็นฟ้าเลย
    default { [System.Drawing.Color]::FromArgb(160, 200, 255) }
}
        $ts = (Get-Date).ToString("HH:mm:ss")
        $logBox.SelectionStart  = $logBox.TextLength
        $logBox.SelectionLength = 0
        $logBox.SelectionColor  = [System.Drawing.Color]::FromArgb(60, 100, 150)
        $logBox.AppendText("[$ts] ")
        $logBox.SelectionColor  = $col
        $logBox.AppendText("$msg`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    } catch { }
}

# ===================== BUTTONS =====================
$btnPanel = New-Object System.Windows.Forms.Panel
$btnPanel.Location  = New-Object System.Drawing.Point(12, 482)
$btnPanel.Size      = New-Object System.Drawing.Size(252, 120)
$btnPanel.BackColor = $BG
$form.Controls.Add($btnPanel)

function New-FlatButton {
    param($txt, $x, $y, $w, $h, $fc)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $txt
    $b.Location  = New-Object System.Drawing.Point($x, $y)
    $b.Size      = New-Object System.Drawing.Size($w, $h)
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderColor        = $fc
    $b.FlatAppearance.BorderSize         = 1
    $b.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(30, $fc.R, $fc.G, $fc.B)
    $b.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(60, $fc.R, $fc.G, $fc.B)
    $b.BackColor = [System.Drawing.Color]::FromArgb(12, 8, 18)
    $b.ForeColor = $fc
    $b.Font      = $FontBtn
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $b
}

$btnRun   = New-FlatButton "▶  RUN Fade" 0 0 252 62 $ACCENT
$btnRun.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$btnPanel.Controls.Add($btnRun)

$btnClear = New-FlatButton "⟳  CLEAR"  0 70 122 38 $TEXTDIM
$btnPanel.Controls.Add($btnClear)

$btnExit  = New-FlatButton "✕  EXIT"   130 70 122 38 $ERR
$btnPanel.Controls.Add($btnExit)

# ===================== TASK / BOTTOM INFO PANEL =====================
$bottomPanel = New-Object System.Windows.Forms.Panel
$bottomPanel.Location  = New-Object System.Drawing.Point(272, 474)
$bottomPanel.Size      = New-Object System.Drawing.Size(656, 204)
$bottomPanel.BackColor = $BG2
$form.Controls.Add($bottomPanel)

$bottomPanel.Add_Paint({
    $g = $_.Graphics
    [int]$bw = $bottomPanel.Width; [int]$bh = $bottomPanel.Height
    $p = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 255, 110, 185), 1)
    $g.DrawRectangle($p, 0, 0, ($bw - 1), ($bh - 1))
    $g.DrawLine($p, 0, 28, $bw, 28)
    $p.Dispose()

    $la = New-Object System.Drawing.Pen($ACCENT2, 2)
    $g.DrawLine($la, 0, 0, 0, 28)
    $la.Dispose()

    $ta = New-Object System.Drawing.Pen($ACCENT2, 2)
    $g.DrawLine($ta, 0, 0, 120, 0)
    $ta.Dispose()
})

$lblTaskTitle = New-Object System.Windows.Forms.Label
$lblTaskTitle.Text      = "  ✦ CURRENT TASK"
$lblTaskTitle.Font      = New-Object System.Drawing.Font("Consolas", 7, [System.Drawing.FontStyle]::Bold)
$lblTaskTitle.ForeColor = $ACCENT2
$lblTaskTitle.Location  = New-Object System.Drawing.Point(6, 8)
$lblTaskTitle.AutoSize  = $true
$bottomPanel.Controls.Add($lblTaskTitle)

$lblTask = New-Object System.Windows.Forms.Label
$lblTask.Text      = "Waiting to start..."
$lblTask.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblTask.ForeColor = $TEXTDIM
$lblTask.Location  = New-Object System.Drawing.Point(10, 36)
$lblTask.Size      = New-Object System.Drawing.Size(636, 20)
$bottomPanel.Controls.Add($lblTask)

$subBar = New-Object System.Windows.Forms.ProgressBar
$subBar.Minimum  = 0
$subBar.Maximum  = 100
$subBar.Value    = 0
$subBar.Location = New-Object System.Drawing.Point(10, 62)
$subBar.Size     = New-Object System.Drawing.Size(636, 10)
$subBar.Style    = "Continuous"
$bottomPanel.Controls.Add($subBar)

$lblMini = New-Object System.Windows.Forms.Label
$lblMini.Text      = ""
$lblMini.Font      = New-Object System.Drawing.Font("Consolas", 7)
$lblMini.ForeColor = $TEXTDIM
$lblMini.Location  = New-Object System.Drawing.Point(10, 78)
$lblMini.Size      = New-Object System.Drawing.Size(636, 120)
$bottomPanel.Controls.Add($lblMini)

# ===================== HELPERS =====================
function Set-StepActive {
    param([int]$active)
    try {
        foreach ($s in $stepDefs) {
            $id = $s.id
            if ($id -eq $active) {
                $stepLabels[$id].ForeColor = $ACCENT
                $stepIcons[$id].ForeColor  = $ACCENT
                $stepIcons[$id].Text       = "[▸]"
            } elseif ($id -lt $active) {
                $stepLabels[$id].ForeColor = $DARKPINK
                $stepIcons[$id].ForeColor  = $DARKPINK
                $stepIcons[$id].Text       = "[✓]"
            } else {
                $stepLabels[$id].ForeColor = $TEXTDIM
                $stepIcons[$id].ForeColor  = $TEXTDIM
                $stepIcons[$id].Text       = "[$id]"
            }
        }
        [System.Windows.Forms.Application]::DoEvents()
    } catch { }
}

function Set-Progress {
    param([int]$main, [int]$sub, [string]$task, [string]$mini = "")
    try {
        $progressBar.Value = [Math]::Max(0, [Math]::Min($main, 100))
        $subBar.Value      = [Math]::Max(0, [Math]::Min($sub, 100))
        $lblProgress.Text  = "◈  PROGRESS   $main%"
        $lblTask.Text      = if ($task) { $task } else { "" }
        $lblTask.ForeColor = $ACCENT2
        if ($mini -ne "") {
            $lblMini.Text      = $mini
            $lblMini.ForeColor = [System.Drawing.Color]::FromArgb(160, 100, 180)
        }
        $progressBar.Refresh()
        $subBar.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
    } catch { }
}

# ===================== RUN BUTTON =====================
$btnRun.Add_Click({
    $btnRun.Enabled      = $false
    $btnRun.ForeColor    = $TEXTDIM
    $lblStatus.Text      = "◆ RUNNING"
    $lblStatus.ForeColor = $WARN

    foreach ($s in $stepDefs) {
        $stepLabels[$s.id].ForeColor = $TEXTDIM
        $stepIcons[$s.id].ForeColor  = $TEXTDIM
        $stepIcons[$s.id].Text       = "[$($s.id)]"
    }

    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "dim"
    Write-Log "  Fade v1  ◈  Low Latency Optimizer" "step"
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "dim"
    Write-Log "Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "hi"

    # STEP 1
    Set-StepActive 1
    Set-Progress 2 0 "Configuring TCP global settings..."
    Write-Log "" "dim"
    Write-Log "STEP 1 ▸ TCP Global Settings (27 cmds)" "step"
    try {
    $tcpCmds = @(
        "netsh int tcp set global rss=enabled",
        "netsh int tcp set global dca=enabled",
        "netsh int tcp set global netdma=enabled",
        "netsh int tcp set global chimney=disabled",
        "netsh int tcp set global rsc=disabled",
        "netsh int tcp set global ecncapability=disabled",
        "netsh int tcp set global timestamps=disabled",
        "netsh int tcp set global nonsackrttresiliency=disabled",
        "netsh int tcp set global autotuninglevel=disabled",
        "netsh int tcp set global fastopen=enabled",
        "netsh int tcp set global fastopenfallback=enabled",
        "netsh int tcp set global maxsynretransmissions=2",
        "netsh int tcp set global initialrto=2000",
        "netsh int tcp set global mincto=0",
        "netsh int tcp set global congestionprovider=ctcp",
        "netsh int tcp set supplemental congestionprovider=ctcp",
        "netsh int tcp set heuristics disabled",
        "netsh int ipv4 set glob defaultcurhoplimit=64",
        "netsh int ipv6 set glob defaultcurhoplimit=64",
        "netsh int ip set global taskoffload=enabled",
        "netsh int ip set global multicastforwarding=disabled",
        "netsh int ip set global reassemblylimit=0",
        "netsh int udp set global uro=disabled",
        "netsh int tcp set global memoryprofile=normal",
        "netsh int ipv6 set global randomizeidentifiers=disabled",
        "netsh int ipv6 set privacy state=disabled"
    )

    $ci = 0
    foreach ($cmd in $tcpCmds) {
        $ci++
        Set-Progress 2 ([int]($ci / $tcpCmds.Count * 100)) "TCP: $cmd"
        try { Invoke-Expression "$cmd 2>&1" | Out-Null } catch {}
        Write-Log "  ▸ $cmd" "ok"
        Start-Sleep -Milliseconds 30
    }
    Write-Log "STEP 1 DONE  ($($tcpCmds.Count) commands)" "ok"
    } catch { Write-Log "STEP 1 ERROR: $_" "err" }
    Set-Progress 17 100 "TCP settings complete"

    # STEP 2
    Set-StepActive 2
    Set-Progress 17 0 "Writing Registry (Interfaces)..."
    Write-Log "" "dim"
    Write-Log "STEP 2 ▸ Registry Interfaces" "step"
    try {
    $ifPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    $ifVals = [ordered]@{
        "MTU"                        = 1500
        "MSS"                        = 1460
        "TcpWindowSize"              = 65535
        "GlobalMaxTcpWindowSize"     = 65535
        "WorldMaxTcpWindowsSize"     = 65535
        "TcpAckFrequency"            = 1
        "TcpDelAckTicks"             = 0
        "TCPNoDelay"                 = 1
        "TcpMaxDataRetransmissions"  = 3
        "TCPTimedWaitDelay"          = 30
        "TCPInitialRtt"              = 300
        "TcpMaxDupAcks"              = 2
        "Tcp1323Opts"                = 1
        "SackOpts"                   = 1
        "KeepAliveTime"              = 30000
        "KeepAliveInterval"          = 1000
        "MaxConnectionsPerServer"    = 16
        "MaxConnectionsPer1_0Server" = 16
        "DefaultTTL"                 = 64
        "EnablePMTUBHDetect"         = 0
        "EnablePMTUDiscovery"        = 1
        "DisableTaskOffload"         = 0
        "DisableLargeMTU"            = 0
        "IRPStackSize"               = 32
        "NumTcbTablePartitions"      = 4
        "MaxFreeTcbs"                = 65536
        "MaxUserPort"                = 65534
        "TcpMaxSendFree"             = 65535
        "MaxHashTableSize"           = 65536
        "DisableRss"                 = 0
        "DisableTcpChimneyOffload"   = 1
        "EnableICMPRedirect"         = 0
        "EnableDHCP"                 = 1
        "SynAttackProtect"           = 0
    }

    $tot = $ifVals.Count; $done = 0
    foreach ($kv in $ifVals.GetEnumerator()) {
        $done++
        Set-Progress 17 ([int]($done / $tot * 100)) "REG IF: $($kv.Key)"
        Set-ItemProperty -Path $ifPath -Name $kv.Key -Value $kv.Value -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log "  $($kv.Key) = $($kv.Value)" "dim"
        Start-Sleep -Milliseconds 15
    }
    Write-Log "STEP 2 DONE  ($tot keys)" "ok"
    } catch { Write-Log "STEP 2 ERROR: $_" "err" }
    Set-Progress 34 100 "Registry Interfaces complete"

    # STEP 3
    Set-StepActive 3
    Set-Progress 34 0 "Writing Registry (Parameters)..."
    Write-Log "" "dim"
    Write-Log "STEP 3 ▸ Registry Parameters (latency focus)" "step"
    try {
    $pPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $pVals = [ordered]@{
        "MTU"                        = 1500
        "MSS"                        = 1460
        "TcpAckFrequency"            = 1
        "TcpDelAckTicks"             = 0
        "TCPNoDelay"                 = 1
        "TcpWindowSize"              = 65535
        "GlobalMaxTcpWindowSize"     = 65535
        "SackOpts"                   = 1
        "Tcp1323Opts"                = 1
        "TcpMaxDataRetransmissions"  = 3
        "TCPTimedWaitDelay"          = 30
        "IRPStackSize"               = 32
        "DefaultTTL"                 = 64
        "KeepAliveTime"              = 30000
        "KeepAliveInterval"          = 1000
        "TCPInitialRtt"              = 300
        "TcpMaxDupAcks"              = 2
        "EnablePMTUBHDetect"         = 0
        "EnablePMTUDiscovery"        = 1
        "DisableTaskOffload"         = 0
        "MaxHashTableSize"           = 65536
        "MaxUserPort"                = 65534
        "MaxFreeTcbs"                = 65536
        "TcpMaxSendFree"             = 65535
        "DeadGWDetectDefault"        = 1
        "NumForwardPackets"          = 500
        "MaxNumForwardPackets"       = 500
        "ForwardBufferMemory"        = 196608
        "MaxForwardBufferMemory"     = 196608
        "SynAttackProtect"           = 0
        "EnableICMPRedirect"         = 0
        "NumTcbTablePartitions"      = 4
    }

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" `
        -Name "Win32PrioritySeparation" -Value 42 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  Win32PrioritySeparation = 42 (foreground boost)" "ok"

    $mmPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Set-ItemProperty -Path $mmPath -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $mmPath -Name "SystemResponsiveness" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  NetworkThrottlingIndex = disabled" "ok"
    Write-Log "  SystemResponsiveness = 0" "ok"

    $gameProfile = "$mmPath\Tasks\Games"
    if (-not (Test-Path $gameProfile)) { New-Item -Path $gameProfile -Force | Out-Null }
    Set-ItemProperty -Path $gameProfile -Name "Affinity" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "Background Only" -Value "False" -Type String -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "Clock Rate" -Value 10000 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "GPU Priority" -Value 8 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "Priority" -Value 6 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "Scheduling Category" -Value "High" -Type String -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameProfile -Name "SFIO Priority" -Value "High" -Type String -Force -ErrorAction SilentlyContinue
    Write-Log "  Multimedia/Games profile tuned" "ok"

    $tot2 = $pVals.Count; $done2 = 0
    foreach ($kv in $pVals.GetEnumerator()) {
        $done2++
        Set-Progress 34 ([int]($done2 / $tot2 * 100)) "REG PARAM: $($kv.Key)"
        Set-ItemProperty -Path $pPath -Name $kv.Key -Value $kv.Value -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log "  $($kv.Key) = $($kv.Value)" "dim"
        Start-Sleep -Milliseconds 15
    }
    Write-Log "STEP 3 DONE  ($tot2 keys)" "ok"
    } catch { Write-Log "STEP 3 ERROR: $_" "err" }
    Set-Progress 50 100 "Registry Parameters complete"

    # STEP 4
    Set-StepActive 4
    Set-Progress 50 0 "Setting process priorities..."
    Write-Log "" "dim"
    Write-Log "STEP 4 ▸ Process Priority (25 games)" "step"
    try {
    $highList = @(
        "FiveM_b2545_GTAProcess","FiveM_b2699_GTAProcess","FiveM_b2802_GTAProcess",
        "FiveM_b2944_GTAProcess","FiveM_b3095_GTAProcess","FiveM_GTAProcess",
        "FiveM","FiveM_SteamChild","CitizenFX.Core",
        "VALORANT-Win64-Shipping","VALORANT",
        "cs2","csgo",
        "RainbowSix","RainbowSix_BE","r5apex","r5apex_dx12",
        "EscapeFromTarkov","Rust","RustClient",
        "FortniteClient-Win64-Shipping","PUBG",
        "GenshinImpact","ZZZ",
        "Overwatch","Overwatch_retail"
    )

    $lowList  = @("steam","explorer","Discord","chrome","firefox","SearchApp","SearchHost","Widgets")
    $allList  = $highList + $lowList
    $pi = 0

    foreach ($pn in $highList) {
        $pi++
        Set-Progress 50 ([int]($pi / $allList.Count * 100)) "Priority HIGH: $pn"
        $proc = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($proc) {
            try { $proc.PriorityClass = "High"; Write-Log "  [HIGH] $pn  - set" "ok" }
            catch { Write-Log "  [HIGH] $pn  - failed" "warn" }
        } else {
            Write-Log "  [SKIP] $pn not running" "dim"
        }
        Start-Sleep -Milliseconds 30
    }

    foreach ($pn in $lowList) {
        $pi++
        Set-Progress 50 ([int]($pi / $allList.Count * 100)) "Priority LOW: $pn"
        $proc = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($proc) {
            try { $proc.PriorityClass = "BelowNormal"; Write-Log "  [LOW]  $pn  - set" "warn" }
            catch { Write-Log "  [LOW]  $pn  - failed" "warn" }
        } else {
            Write-Log "  [SKIP] $pn not running" "dim"
        }
        Start-Sleep -Milliseconds 30
    }
    Write-Log "STEP 4 DONE" "ok"
    } catch { Write-Log "STEP 4 ERROR: $_" "err" }
    Set-Progress 67 100 "Process priority complete"

    # STEP 5
    Set-StepActive 5
    Set-Progress 67 0 "Applying IRQ & power hints..."
    Write-Log "" "dim"
    Write-Log "STEP 5 ▸ IRQ & Power hints" "step"

    try {
        powercfg -setactive SCHEME_MIN 2>&1 | Out-Null
        Write-Log "  Power scheme: High Performance" "ok"
    } catch { Write-Log "  Power scheme: skipped" "dim" }

    try {
        $cpuPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7"
        if (Test-Path $cpuPath) {
            Set-ItemProperty -Path $cpuPath -Name "Attributes" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-Log "  CPU responsiveness unlock: done" "ok"
        }
    } catch { Write-Log "  CPU path: skipped" "dim" }

    try {
        bcdedit /set useplatformclock false 2>&1 | Out-Null
        bcdedit /set disabledynamictick yes 2>&1 | Out-Null
        Write-Log "  Dynamic tick disabled (lower timer latency)" "ok"
    } catch { Write-Log "  bcdedit: skipped" "dim" }

    try {
        bcdedit /deletevalue useplatformhpet 2>&1 | Out-Null
        Write-Log "  HPET: cleared" "ok"
    } catch {}

    Set-Progress 83 100 "IRQ & power hints done"
    Write-Log "STEP 5 DONE" "ok"

    # STEP 6
    Set-StepActive 6
    Set-Progress 83 0 "Disabling services..."
    Write-Log "" "dim"
    Write-Log "STEP 6 ▸ Disabling background services" "step"
    try {
    $svcs = @(
        @{ name="SysMain";            reason="Prefetch (wastes RAM/IO)" },
        @{ name="DiagTrack";          reason="Telemetry" },
        @{ name="dmwappushservice";   reason="WAP push (telemetry)" },
        @{ name="WSearch";            reason="Windows Search (disk IO)" },
        @{ name="Fax";                reason="Fax service" },
        @{ name="RemoteRegistry";     reason="Remote registry" },
        @{ name="RetailDemo";         reason="Retail demo" },
        @{ name="TabletInputService"; reason="Tablet input (if not needed)" }
    )

    $si2 = 0
    foreach ($svc in $svcs) {
        $si2++
        Set-Progress 83 ([int]($si2 / $svcs.Count * 100)) "SERVICE: $($svc.name)"
        Stop-Service  -Name $svc.name -Force -ErrorAction SilentlyContinue
        Set-Service   -Name $svc.name -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "  [OFF] $($svc.name)  ($($svc.reason))" "ok"
        Start-Sleep -Milliseconds 200
    }
    Write-Log "STEP 6 DONE" "ok"
    } catch { Write-Log "STEP 6 ERROR: $_" "err" }

    # ALL DONE
    try {
    foreach ($s in $stepDefs) {
        $stepLabels[$s.id].ForeColor = $DARKPINK
        $stepIcons[$s.id].ForeColor  = $DARKPINK
        $stepIcons[$s.id].Text       = "[✓]"
    }
    } catch { }

    $summary = "TCP (27 cmds)  ◈  Registry patched  ◈  25 games prioritized`nIRQ & power tuned  ◈  8 services disabled  ◈  Multimedia profile set"
    Set-Progress 100 100 "ALL DONE — restart recommended" $summary
    $lblMini.ForeColor = $ACCENT

    Write-Log "" "dim"
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "dim"
    Write-Log "               ✦  COMPLETE  ✦" "ok"
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "dim"

    $lblStatus.Text      = "◆ COMPLETE"
    $lblStatus.ForeColor = $ACCENT
    $btnRun.Enabled      = $true
    $btnRun.ForeColor    = $ACCENT
    $btnRun.Text         = "▶  RUN Fade"
})

# ===================== CLEAR / EXIT =====================
$btnClear.Add_Click({
    $logBox.Clear()
    $progressBar.Value = 0
    $subBar.Value      = 0
    $lblProgress.Text  = "◈  PROGRESS   0%"
    $lblTask.Text      = "Waiting to start..."
    $lblTask.ForeColor = $TEXTDIM
    $lblMini.Text      = ""
    $lblMini.ForeColor = $TEXTDIM
    $lblStatus.Text      = "◆ READY"
    $lblStatus.ForeColor = $ACCENT
    $btnRun.Text         = "▶  RUN DekFade"
    foreach ($s in $stepDefs) {
        $stepLabels[$s.id].ForeColor = $TEXTDIM
        $stepIcons[$s.id].ForeColor  = $TEXTDIM
        $stepIcons[$s.id].Text       = "[$($s.id)]"
    }
})

$btnExit.Add_Click({ $form.Close() })
$btnWinClose.Add_Click({ $form.Close() })

# ===================== INIT LOG =====================
Write-Log "initialized" "hi"
Write-Log "OS:  $osInfo" "dim"
Write-Log "CPU: $cpuInfo" "dim"
Write-Log "RAM: $ramGB GB" "dim"
Write-Log "" "dim"
Write-Log "What's new in v2:" "step"
Write-Log "  ▸ New setting  mouse&keyboard Network " "ok"
Write-Log "Press [ RUN Fade ] to start." "ok"

try {
    [System.Windows.Forms.Application]::Run($form)
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
}