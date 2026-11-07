@echo off
"%~dp0pcap_investigator\.venv\Scripts\python.exe" "%~dp0pcap_investigator\run_real_capture.py"
if errorlevel 1 (
    echo.
    echo Real-data analysis failed. Keep this window open to read the error.
)
pause
