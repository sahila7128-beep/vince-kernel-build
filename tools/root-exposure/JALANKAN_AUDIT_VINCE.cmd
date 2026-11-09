@echo off
setlocal EnableExtensions DisableDelayedExpansion
title VINCE - Pemeriksaan Root dan Modul
set "WORKDIR=%~dp0"
set "VINCE_WORK_DIR=%WORKDIR%"
set "REPORT=%WORKDIR%vince-root-audit.txt"
set "ERRORLOG=%WORKDIR%vince-audit-error.txt"
set "AUDITSCRIPT=%WORKDIR%vince-security-audit.sh"
set "ADB="

if /i "%~1"=="/help" goto show_help

echo ============================================================
echo    VINCE ROOT + MODUL AUDIT - SATU KLIK
echo ============================================================
echo.
echo Audit hanya membaca status, tidak mengubah HP.
echo Pastikan Redmi 5 Plus terhubung dengan kabel USB.
echo Aktifkan USB debugging dan izinkan ADB di layar HP.
echo Berikan izin FinaSU ke ADB Shell jika diminta.
echo.

if exist "%WORKDIR%platform-tools\adb.exe" set "ADB=%WORKDIR%platform-tools\adb.exe"
if defined ADB goto have_adb
where adb.exe >nul 2>&1
if not errorlevel 1 set "ADB=adb.exe"
if defined ADB goto have_adb

echo [1/5] ADB belum ada. Mengunduh Android Platform-Tools dari Google...
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $d=$env:VINCE_WORK_DIR; $z=Join-Path $d 'platform-tools-windows.zip'; Invoke-WebRequest -UseBasicParsing -Uri 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip' -OutFile $z; Expand-Archive -LiteralPath $z -DestinationPath $d -Force; Remove-Item -LiteralPath $z -Force"
if errorlevel 1 goto adb_download_failed
if not exist "%WORKDIR%platform-tools\adb.exe" goto adb_download_failed
set "ADB=%WORKDIR%platform-tools\adb.exe"

:have_adb
echo [1/5] ADB siap.
if exist "%AUDITSCRIPT%" goto have_script

echo [2/5] Mengambil skrip audit dari commit GitHub yang sudah diuji...
powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/sahila7128-beep/vince-kernel-build/0d809bb0aeeee4afd3be36a5157c8594dcc5aeaa/tools/root-exposure/vince-security-audit.sh' -OutFile (Join-Path $env:VINCE_WORK_DIR 'vince-security-audit.sh')"
if errorlevel 1 goto script_download_failed
if not exist "%AUDITSCRIPT%" goto script_download_failed

:have_script
echo [2/5] Skrip audit siap.
echo [3/5] Mengecek koneksi HP...
"%ADB%" devices
"%ADB%" get-state > "%WORKDIR%vince-adb-status.txt" 2>&1
findstr.exe /x /c:"device" "%WORKDIR%vince-adb-status.txt" >nul 2>&1
if errorlevel 1 goto device_failed
del /q "%WORKDIR%vince-adb-status.txt" >nul 2>&1

echo.
echo [4/5] Mengirim skrip sementara ke HP...
"%ADB%" push "%AUDITSCRIPT%" "/data/local/tmp/vince-security-audit.sh"
if errorlevel 1 goto push_failed

echo.
echo [5/5] Memeriksa modul dan konfigurasi. Lihat HP jika ada izin FinaSU...
echo Tidak perlu membuka aplikasi perbankan.
echo.
if exist "%REPORT%" (
    copy /y "%REPORT%" "%WORKDIR%vince-root-audit-sebelumnya.txt" >nul 2>&1
)
"%ADB%" shell su -c "sh /data/local/tmp/vince-security-audit.sh" > "%REPORT%" 2> "%ERRORLOG%"
if errorlevel 1 goto root_failed
findstr.exe /c:"No shell commands modified packages" "%REPORT%" >nul 2>&1
if errorlevel 1 goto incomplete_report

echo.
echo ============================================================
echo    SELESAI - BERHASIL MENYIMPAN HASIL AUDIT
echo ============================================================
echo.
echo File hasil:
echo "%REPORT%"
echo.
echo Periksa isi TXT lalu kirim vince-root-audit.txt ke ChatGPT.
echo Jangan mengirim keybox XML, PIN, OTP, atau data bank.
echo Hasil audit bukan jaminan aplikasi bank akan menerima perangkat.
echo.
start "" notepad.exe "%REPORT%"
pause
exit /b 0

:show_help
echo Klik dua kali JALANKAN_AUDIT_VINCE.cmd pada Windows 10/11.
echo Gunakan kabel USB, aktifkan USB debugging pada HP.
echo Jika ADB belum ada, file ini mengunduh dari situs resmi Google.
echo Izin ADB Shell untuk membaca modul harus diberikan di FinaSU.
echo File laporan akan muncul di folder yang sama: vince-root-audit.txt
exit /b 0

:adb_download_failed
echo.
echo [GAGAL] Tidak dapat mengunduh ADB resmi dari Google.
echo Pastikan PC punya internet, lalu klik ulang file ini.
goto failed

:script_download_failed
echo.
echo [GAGAL] Tidak dapat membaca skrip audit dari repository.
echo Jika menggunakan paket ZIP, ekstrak kedua file ke folder yang sama.
goto failed

:device_failed
echo.
echo [GAGAL] HP belum terdeteksi sebagai device.
echo Lihat pesan di bawah:
if exist "%WORKDIR%vince-adb-status.txt" type "%WORKDIR%vince-adb-status.txt"
echo Aktifkan USB debugging; setujui izin di HP; gunakan kabel data.
echo Tutup emulator atau cabut perangkat Android lain jika terhubung.
goto failed

:push_failed
echo.
echo [GAGAL] Tidak dapat mengirim skrip ke /data/local/tmp.
echo Coba sambungkan ulang kabel dan pastikan izin USB debugging.
goto failed

:root_failed
echo.
echo [GAGAL] Audit tidak selesai. Pastikan akses root ADB Shell di FinaSU diizinkan.
if exist "%ERRORLOG%" type "%ERRORLOG%"
echo Jangan mengubah pengaturan kernel atau keybox untuk mengatasi ini.
goto failed

:incomplete_report
echo.
echo [GAGAL] Laporan tampaknya terpotong atau tidak lengkap.
if exist "%ERRORLOG%" type "%ERRORLOG%"
echo Periksa FinaSU Manager dan coba jalankan ulang.
goto failed

:failed
echo.
echo Jika masih gagal, foto pesan pada jendela ini dan kirim ke ChatGPT.
pause
exit /b 1
