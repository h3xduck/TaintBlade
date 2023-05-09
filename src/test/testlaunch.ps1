Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class User32 {
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
    }
"@

$testNumber = (Get-ChildItem -Directory).Count
$testCounter = 1

function runTest {
    param( [String]$testDir )
    Write-Host 'Running test'$testCounter'/'$testNumber' at: '$testDir
    cd $testDir

    if(!(Test-Path "programinfo.txt")){
        Write-Host "No programinfo.txt file found, ignoring test`n" -ForegroundColor Red
        $script:testCounter++
        cd ..
        return
    }

    if(!(Test-Path "testset.txt")){
        Write-Host "No testset.txt file found, ignoring test`n" -ForegroundColor Red
        $script:testCounter++
        cd ..
        return
    }

    $programInfo = (Get-Content -Path .\programinfo.txt)
    Write-Host 'Running program'$programInfo

    $serverProcess = Start-Process -FilePath "..\..\..\samples\tcp_server.exe" -PassThru
    $user32 = New-Object User32
    $null = $user32::SetForegroundWindow((Get-Process -id $pid).MainWindowHandle)
    Start-Sleep -Seconds 0.5

    $testProcess = Start-Process cmd -ArgumentList '/k', "..\..\external\pin-3.25-98650-g8f6168173-msvc-windows\pin-3.25-98650-g8f6168173-msvc-windows\pin.exe -follow_execv -t ..\..\PinTracer\x64\Release\PinTracer.dll -o pinlog.dfx -s syspinlog.dfx -i imgpinlog.dfx -d debuglogfile.dfx -test testset.txt -taint taintsources.txt -- ..\..\..\samples\$programInfo" -PassThru
    $user32 = New-Object User32
    $null = $user32::SetForegroundWindow((Get-Process -id $pid).MainWindowHandle)

    Write-Host 'Press any key to go to the next test...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    Stop-Process -Id $serverProcess.Id
    Stop-Process -Id $testProcess.Id

    $script:testCounter++

    Write-Host ''

    cd ..
}

#Info
if($testNumber -gt 0){
    Write-Host "Found"$testNumber" test to run" -ForegroundColor Green
}else{
    Write-Host "No tests found" -ForegroundColor Red
    Exit
}

#Iterate over all directories in the test directory to find all test sets
Get-ChildItem -Directory | ForEach-Object {
    $directoryName = $_.Name
    runTest($directoryName)
}