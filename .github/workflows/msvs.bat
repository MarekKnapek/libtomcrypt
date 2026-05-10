echo on

if "%~1"=="MSVC-Debug" goto mk_msvc_debug
if "%~1"=="MSVC-Release" goto mk_msvc_release
if "%~1"=="clang-Debug" goto mk_clang_debug
if "%~1"=="clang-Release" goto mk_clang_release
goto :mk_bad
:mk_msvc_debug
if "%~2"=="x86" goto mk_msvc_debug_x86
if "%~2"=="x64" goto mk_msvc_debug_x64
goto :mk_bad
:mk_msvc_release
if "%~2"=="x86" goto mk_msvc_release_x86
if "%~2"=="x64" goto mk_msvc_release_x64
goto :mk_bad
:mk_clang_debug
if "%~2"=="x86" goto mk_clang_debug_x86
if "%~2"=="x64" goto mk_clang_debug_x64
goto :mk_bad
:mk_clang_release
if "%~2"=="x86" goto mk_clang_release_x86
if "%~2"=="x64" goto mk_clang_release_x64
goto :mk_bad

:mk_msvc_debug_x86
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Debug|x86" /Project "test" /ProjectConfig "MSVC-Debug|Win32" /Out "%~dp0..\..\msvs\test-MSVC-Debug-x86.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Debug|x86" /Project "timing" /ProjectConfig "MSVC-Debug|Win32" /Out "%~dp0..\..\msvs\timing-MSVC-Debug-x86.txt" || goto :mk_bad
"%~dp0..\..\msvs\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_msvc_release_x86
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Release|x86" /Project "test" /ProjectConfig "MSVC-Release|Win32" /Out "%~dp0..\..\msvs\test-MSVC-Release-x86.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Release|x86" /Project "timing" /ProjectConfig "MSVC-Release|Win32" /Out "%~dp0..\..\msvs\timing-MSVC-Release-x86.txt" || goto :mk_bad
"%~dp0..\..\msvs\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_msvc_debug_x64
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Debug|x64" /Project "test" /ProjectConfig "MSVC-Debug|x64" /Out "%~dp0..\..\msvs\test-MSVC-Debug-x64.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Debug|x64" /Project "timing" /ProjectConfig "MSVC-Debug|x64" /Out "%~dp0..\..\msvs\timing-MSVC-Debug-x64.txt" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_msvc_release_x64
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Release|x64" /Project "test" /ProjectConfig "MSVC-Release|x64" /Out "%~dp0..\..\msvs\test-MSVC-Release-x64.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "MSVC-Release|x64" /Project "timing" /ProjectConfig "MSVC-Release|x64" /Out "%~dp0..\..\msvs\timing-MSVC-Release-x64.txt" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_clang_debug_x86
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Debug|x86" /Project "test" /ProjectConfig "clang-Debug|Win32" /Out "%~dp0..\..\msvs\test-clang-Debug-x86.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Debug|x86" /Project "timing" /ProjectConfig "clang-Debug|Win32" /Out "%~dp0..\..\msvs\timing-clang-Debug-x86.txt" || goto :mk_bad
"%~dp0..\..\msvs\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_clang_release_x86
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Release|x86" /Project "test" /ProjectConfig "clang-Release|Win32" /Out "%~dp0..\..\msvs\test-clang-Release-x86.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Release|x86" /Project "timing" /ProjectConfig "clang-Release|Win32" /Out "%~dp0..\..\msvs\timing-clang-Release-x86.txt" || goto :mk_bad
"%~dp0..\..\msvs\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_clang_debug_x64
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Debug|x64" /Project "test" /ProjectConfig "clang-Debug|x64" /Out "%~dp0..\..\msvs\test-clang-Debug-x64.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Debug|x64" /Project "timing" /ProjectConfig "clang-Debug|x64" /Out "%~dp0..\..\msvs\timing-clang-Debug-x64.txt" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\timing.exe" || goto :mk_bad
goto :mk_gud
:mk_clang_release_x64
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Release|x64" /Project "test" /ProjectConfig "clang-Release|x64" /Out "%~dp0..\..\msvs\test-clang-Release-x64.txt" || goto :mk_bad
"c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "clang-Release|x64" /Project "timing" /ProjectConfig "clang-Release|x64" /Out "%~dp0..\..\msvs\timing-clang-Release-x64.txt" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\x64\%~1\timing.exe" || goto :mk_bad
goto :mk_gud

:mk_gud
echo Gud.
exit /b 0

:mk_bad
echo Bad.
exit /b 1

:mk_end
