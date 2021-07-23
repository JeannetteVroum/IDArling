@echo off

REM Sometimes we need to temporarily disable idarling by removing the plugin so it
REM does not load to avoid.
REM A better way is to set IDAUSR to a path that does not exists so no plugin is loaded
REM https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml
set IDAUSR=C:\notexist

REM Start IDA
"C:\Program Files\IDA Pro 7.5\ida.exe"