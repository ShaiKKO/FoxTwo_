@echo off
setlocal

rem Simple build script for monitor_client.lib and monitor_cli.exe

if not defined DevEnvDir (
    echo Building with default CL from PATH...
) else (
    echo Using Visual Studio environment from %DevEnvDir%...
)

cl /nologo /W4 /EHsc /I.. monitor_client.c monitor_cli.c /link /out:monitor_cli.exe
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build succeeded. Run monitor_cli.exe as an elevated user on a system with the driver loaded.

endlocal
