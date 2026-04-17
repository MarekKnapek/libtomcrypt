echo on

setlocal
if exist "c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com" goto :mk_vs_enterprise
if exist "c:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.com" goto :mk_vs_community
goto :mk_bad
:mk_vs_enterprise
set mk_vs_devenv="c:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\IDE\devenv.com"
goto :mk_vs_next
:mk_vs_community
set mk_vs_devenv="c:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.com"
goto :mk_vs_next
:mk_vs_next

if "%~1"=="MSVC-Debug" goto :mk_conf_msvc_debug
if "%~1"=="MSVC-Release" goto :mk_conf_msvc_release
if "%~1"=="clang-Debug" goto :mk_conf_clang_debug
if "%~1"=="clang-Release" goto :mk_conf_clang_release
goto :mk_bad
:mk_conf_msvc_debug
set mk_sln_conf=MSVC-Debug
set mk_prj_conf=MSVC-Debug
goto :mk_conf_next
:mk_conf_msvc_release
set mk_sln_conf=MSVC-Release
set mk_prj_conf=MSVC-Release
goto :mk_conf_next
:mk_conf_clang_debug
set mk_sln_conf=clang-Debug
set mk_prj_conf=clang-Debug
goto :mk_conf_next
:mk_conf_clang_release
set mk_sln_conf=clang-Release
set mk_prj_conf=clang-Release
goto :mk_conf_next
:mk_conf_next

if "%~2"=="x86" goto :mk_arch_i386
if "%~2"=="x64" goto :mk_arch_amd64
goto :mk_bad
:mk_arch_i386
set mk_sln_arch=x86
set mk_prj_arch=Win32
goto :mk_arch_next
:mk_arch_amd64
set mk_sln_arch=x64
set mk_prj_arch=x64
goto :mk_arch_next
:mk_arch_next

%mk_vs_devenv% "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "%mk_sln_conf%|%mk_sln_arch%" /Project "test" /ProjectConfig "%mk_prj_conf%|%mk_prj_arch%" /Out "%~dp0..\..\msvs\test-%mk_prj_conf%-%mk_prj_arch%.txt" || goto :mk_bad
%mk_vs_devenv% "%~dp0..\..\msvs\libtomcrypt.slnx" /Build "%mk_sln_conf%|%mk_sln_arch%" /Project "timing" /ProjectConfig "%mk_prj_conf%|%mk_prj_arch%" /Out "%~dp0..\..\msvs\test-%mk_prj_conf%-%mk_prj_arch%.txt" || goto :mk_bad
pushd "%~dp0..\..\" || goto :mk_bad
"%~dp0..\..\msvs\build\out\%mk_prj_arch%-%mk_prj_conf%\test.exe" || goto :mk_bad
"%~dp0..\..\msvs\build\out\%mk_prj_arch%-%mk_prj_conf%\timing.exe" || goto :mk_bad
popd || goto :mk_bad
goto :mk_gud

:mk_gud
endlocal
echo Gud.
exit /b 0

:mk_bad
endlocal
echo Bad.
exit /b 1

:mk_end
