echo on

call "%~dp0msvs.bat" "clang-Debug" "x64" || goto :mk_bad
call "%~dp0msvs.bat" "clang-Debug" "x86" || goto :mk_bad
call "%~dp0msvs.bat" "clang-Release" "x64" || goto :mk_bad
call "%~dp0msvs.bat" "clang-Release" "x86" || goto :mk_bad
call "%~dp0msvs.bat" "MSVC-Debug" "x64" || goto :mk_bad
call "%~dp0msvs.bat" "MSVC-Debug" "x86" || goto :mk_bad
call "%~dp0msvs.bat" "MSVC-Release" "x64" || goto :mk_bad
call "%~dp0msvs.bat" "MSVC-Release" "x86" || goto :mk_bad

:mk_gud
echo Gud.
exit /b 0

:mk_bad
echo Bad.
exit /b 1

:mk_end
