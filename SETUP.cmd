@echo off
setlocal
cd /d "%~dp0pcap_investigator"
if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>&1
    if errorlevel 1 (
        python -m venv .venv
    ) else (
        py -3 -m venv .venv
    )
    if errorlevel 1 goto python_failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto packages_failed
".venv\Scripts\python.exe" check_setup.py
if errorlevel 1 goto capture_missing
echo.
echo Setup complete. Run REAL_DATA.cmd or HTTPS_RESPONSE_LAB.cmd from this folder.
goto done

:python_failed
echo Python 3 was not found. Install it, then rerun SETUP.cmd.
goto done
:packages_failed
echo Python package installation failed. Check your internet connection and rerun SETUP.cmd.
goto done
:capture_missing
echo Install the missing capture component shown above, then rerun SETUP.cmd.
:done
pause
