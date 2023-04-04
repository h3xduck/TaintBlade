$pinExecutablePath = "..\external\pin-3.25-98650-g8f6168173-msvc-windows\pin-3.25-98650-g8f6168173-msvc-windows\pin.exe"
$pinArguments = "-t ..\PinTracer\x64\Release\PinTracer.dll -o pinlog.txt -s syspinlog.txt -i imgpinlog.txt -d debuglogfile.txt -test testset.txt -- ..\..\samples\tcp_client.exe 127.0.0.1"

Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class User32 {
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
    }
"@

$serverProcess = Start-Process -FilePath "..\..\samples\tcp_server.exe" -PassThru
#[System.Windows.Forms.SendKeys]::SendWait("%{TAB}")
Start-Sleep -Seconds 0.5

$testProcess = Start-Process cmd -ArgumentList '/k', '..\external\pin-3.25-98650-g8f6168173-msvc-windows\pin-3.25-98650-g8f6168173-msvc-windows\pin.exe -t ..\PinTracer\x64\Release\PinTracer.dll -o pinlog.txt -s syspinlog.txt -i imgpinlog.txt -d debuglogfile.txt -test testset.txt -- ..\..\samples\tcp_client.exe 127.0.0.1' -PassThru
$user32 = New-Object User32
$user32::SetForegroundWindow((Get-Process -id $pid).MainWindowHandle)

Write-Host -NoNewLine 'Press any key to close test...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Stop-Process -Id $serverProcess.Id
Stop-Process -Id $testProcess.Id
