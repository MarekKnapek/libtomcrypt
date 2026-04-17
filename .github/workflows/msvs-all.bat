echo on

call "%~dp0msvs.bat" "MSVC-Debug" "x86"
call "%~dp0msvs.bat" "MSVC-Release" "x86"
call "%~dp0msvs.bat" "clang-Debug" "x86"
call "%~dp0msvs.bat" "clang-Release" "x86"
call "%~dp0msvs.bat" "MSVC-Debug" "x64"
call "%~dp0msvs.bat" "MSVC-Release" "x64"
call "%~dp0msvs.bat" "clang-Debug" "x64"
call "%~dp0msvs.bat" "clang-Release" "x64"
