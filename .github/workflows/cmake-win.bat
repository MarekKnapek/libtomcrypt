echo on

pushd .
cd "%~dp0..\.."

rem fetch libtommath
if exist build\ goto :mk_skip_1
mkdir build || goto :mk_bad
:mk_skip_1
cd build || goto :mk_bad
if exist libtommath\ goto :mk_skip_2
git clone --depth 1 https://github.com/MarekKnapek/libtommath.git || goto :mk_bad
:mk_skip_2
cd .. || goto :mk_bad

rem build libtommath for i386
cd build || goto :mk_bad
cd libtommath || goto :mk_bad
if exist build\ goto :mk_skip_3
mkdir build || goto :mk_bad
:mk_skip_3
cd build || goto :mk_bad
if exist i386\ goto :mk_skip_4
mkdir i386 || goto :mk_bad
:mk_skip_4
cd i386 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A Win32 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

rem build libtomcrypt for i386
cd build || goto :mk_bad
if exist i386\ goto :mk_skip_5
mkdir i386 || goto :mk_bad
:mk_skip_5
cd i386 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A Win32 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-DLTC_NO_PROTOTYPES -D_CRT_SECURE_NO_WARNINGS" || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

rem build libtomcrypt tests for i386
cd tests || goto :mk_bad
if exist build\ goto :mk_skip_6
mkdir build || goto :mk_bad
:mk_skip_6
cd build || goto :mk_bad
if exist i386\ goto :mk_skip_7
mkdir i386 || goto :mk_bad
:mk_skip_7
cd i386 || goto :mk_bad
set libtomcrypt_DIR=..\..\..\build\i386 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A Win32 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-D_CRT_SECURE_NO_WARNINGS" || goto :mk_bad
if not exist "%~dp0..\..\tests\build\i386\libtommath.lib" goto :mk_skip_8
del "%~dp0..\..\tests\build\i386\libtommath.lib"
:mk_skip_8
mklink /h "%~dp0..\..\tests\build\i386\libtommath.lib" "%~dp0..\..\build\libtommath\build\i386\Release\tommath.lib" || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd Release || goto :mk_bad
test-ltc.exe && goto :mk_skip_9
echo Some test(s) failed.
:mk_skip_9
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

rem build libtommath for amd64
cd build || goto :mk_bad
cd libtommath || goto :mk_bad
if exist build\ goto :mk_skip_10
mkdir build || goto :mk_bad
:mk_skip_10
cd build || goto :mk_bad
if exist amd64\ goto :mk_skip_11
mkdir amd64 || goto :mk_bad
:mk_skip_11
cd amd64 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A x64 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

rem build libtomcrypt for amd64
cd build || goto :mk_bad
if exist amd64\ goto :mk_skip_12
mkdir amd64 || goto :mk_bad
:mk_skip_12
cd amd64 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A x64 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-DLTC_NO_PROTOTYPES -D_CRT_SECURE_NO_WARNINGS" || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

rem build libtomcrypt tests for amd64
cd tests || goto :mk_bad
if exist build\ goto :mk_skip_13
mkdir build || goto :mk_bad
:mk_skip_13
cd build || goto :mk_bad
if exist amd64\ goto :mk_skip_14
mkdir amd64 || goto :mk_bad
:mk_skip_14
cd amd64 || goto :mk_bad
set libtomcrypt_DIR=..\..\..\build\amd64 || goto :mk_bad
cmake -G "Visual Studio 18 2026" -A x64 -S ..\.. -B . -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-D_CRT_SECURE_NO_WARNINGS" || goto :mk_bad
if not exist "%~dp0..\..\tests\build\amd64\libtommath.lib" goto :mk_skip_15
del "%~dp0..\..\tests\build\amd64\libtommath.lib"
:mk_skip_15
mklink /h "%~dp0..\..\tests\build\amd64\libtommath.lib" "%~dp0..\..\build\libtommath\build\amd64\Release\tommath.lib" || goto :mk_bad
cmake --build . --config Release || goto :mk_bad
cd Release || goto :mk_bad
test-ltc.exe && goto :mk_skip_16
echo Some test(s) failed.
:mk_skip_16
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad
cd .. || goto :mk_bad

popd || goto :mk_bad
goto :mk_gud

:mk_gud
echo Gud.
exit /b 0

:mk_bad
echo Bad.
exit /b 1

:mk_end
