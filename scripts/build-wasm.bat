::  This file is part of Custodes SDC.
::
:: Custodes SDC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
::
:: Custodes SDC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
::
:: You should have received a copy of the GNU General Public License along with Custodes SDC. If not, see <https://www.gnu.org/licenses/>.

@echo off
setlocal

if "%EMSDK%"=="" (
    echo Error: EMSDK environment variable is not set.
    echo Please run 'emsdk_env.bat' before executing this script.
    exit /b 1
)

echo Configuring WASM target...
cmake --preset wasm-release
if %errorlevel% neq 0 (
    echo CMake configuration failed.
    exit /b %errorlevel%
)

echo Building WASM target...
cmake --build --preset wasm-release
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b %errorlevel%
)

echo WASM build complete!
endlocal