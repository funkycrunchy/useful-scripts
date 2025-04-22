@echo off

echo Stopping Hamachi service if running...
sc stop Hamachi2Svc
if %errorlevel% == 0 timeout 3

echo Restarting Hamachi service...
sc start Hamachi2Svc
if %errorlevel% neq 0 goto Error

rem Successful
exit /b 0

:Error
set result=%errorlevel%
echo Error %result%
exit /b %result%