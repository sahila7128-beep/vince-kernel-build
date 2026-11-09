@echo off
setlocal
title Pemeriksaan KAREPMU + MODUL (BACA SAJA)
cd /d "%~dp0"
echo ============================================================
echo  ANALISIS KAREPMU.APK + MODUL.ZIP TANPA INSTAL DI HP
echo ============================================================
echo.
echo Pastikan KAREPMU.apk dan MODUL.zip ada di folder Downloads.
echo File akan dibaca di PC saja, tanpa ADB, root, atau internet.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ANALISIS_KAREPMU_MODUL.ps1"
if errorlevel 1 (
  echo.
  echo GAGAL. Pastikan kedua file APK dan ZIP ada di folder Downloads.
  echo Jika muncul kesalahan, ambil foto pesan di jendela ini.
) else (
  echo.
  echo SELESAI. File LAPORAN_KAREPMU_MODUL.txt dibuat pada folder ini.
  echo Baca dahulu dan kirimkan file laporan jika tidak ada rahasia.
)
echo.
pause
exit /b
