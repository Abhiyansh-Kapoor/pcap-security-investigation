@echo off
"%~dp0pcap_investigator\.venv\Scripts\python.exe" "%~dp0pcap_investigator\incident_lab.py"
if errorlevel 1 (
    echo.
    echo HTTPS capture failed. Keep this window open to read the error.
)
pause
