param([string]$ApkPath="", [string]$ModulePath="")
$ErrorActionPreference="Stop"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$dir=Split-Path -Parent $PSCommandPath
$downloads=Join-Path $env:USERPROFILE "Downloads"
function Locate($name,$given) {
 if ($given -and (Test-Path -LiteralPath $given)) { return (Resolve-Path -LiteralPath $given).Path }
 foreach($d in @($dir,$downloads)) { $p=Join-Path $d $name; if(Test-Path -LiteralPath $p){ return $p } }
 throw "Tidak ditemukan: $name. Simpan file itu ke folder Downloads lalu klik ulang."
}
$apk=Locate "KAREPMU.apk" $ApkPath
$mod=Locate "MODUL.zip" $ModulePath
$r=New-Object System.Collections.Generic.List[string]
function Put($v){[void]$r.Add([string]$v)}
function ReadEntry($e,$limit=65536){
 if($null -eq $e -or $e.Length -gt $limit){return $null}
 $s=$e.Open()
 try {
  $b=New-Object byte[] ([int]$e.Length);$offset=0
  while($offset -lt $b.Length){
   $n=$s.Read($b,$offset,$b.Length-$offset);if($n -le 0){break};$offset+=$n
  }
  if($offset -ne $b.Length){return $null};return ,$b
 }finally{$s.Dispose()}
}
function U16($b,$i){[BitConverter]::ToUInt16($b,$i)}
function U32($b,$i){[BitConverter]::ToUInt32($b,$i)}
function PoolStrings($b){
 $ss=New-Object System.Collections.Generic.List[string]
 if($b.Length -lt 8 -or (U16 $b 0) -ne 3){return $ss}
 $p=8;$lim=[Math]::Min([int](U32 $b 4),$b.Length)
 while($p+28 -le $lim){
  $type=U16 $b $p
  $head=U16 $b ($p+2)
  $sz=[int](U32 $b ($p+4))
  if($sz -lt 8 -or $p+$sz -gt $lim){break}
  if($type -eq 1){
   $n=[Math]::Min(100000,[int](U32 $b ($p+8)))
   $flags=U32 $b ($p+16)
   $start=[int](U32 $b ($p+20))
   for($i=0;$i -lt $n;$i++){
    $o=$p+$head+4*$i
    if($o+4 -gt $p+$sz){break}
    $k=$p+$start+[int](U32 $b $o)
    if($k -ge $p+$sz){continue}
    try{
     if(($flags -band 256) -ne 0){
      $len=[int]$b[$k];$k++
      if($len -ge 128){$k++}
      $len=[int]$b[$k];$k++
      if($len -ge 128){$len=(($len -band 127) -shl 8)+$b[$k];$k++}
      if($k+$len -le $p+$sz){[void]$ss.Add([Text.Encoding]::UTF8.GetString($b,$k,$len))}
     } else {
      $len=[int](U16 $b $k);$k+=2
      if($len -ge 32768){$len=(($len -band 32767) -shl 16)+(U16 $b $k);$k+=2}
      if($k+2*$len -le $p+$sz){[void]$ss.Add([Text.Encoding]::Unicode.GetString($b,$k,$len*2))}
     }
    }catch{}
   }
   break
  }
  $p+=$sz
 }
 return $ss
}
Put "KAREPMU + MODUL: PEMERIKSAAN STATIS (TIDAK DIINSTAL / TIDAK DIJALANKAN)"
Put "Tanggal: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Put "Bukan pemindaian antivirus; tidak dapat memastikan perilaku dinamis atau aman untuk WhatsApp."
foreach($p in @($apk,$mod)){
 $i=Get-Item -LiteralPath $p
 Put ""
 Put "FILE: $($i.Name) SIZE: $($i.Length) SHA256: $((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash)"
}
foreach($item in @(@("APK",$apk),@("MODUL",$mod))){
 $mode=$item[0];$path=$item[1]
 Put "";Put "================== $mode =================="
 try {
  $zip=[IO.Compression.ZipFile]::OpenRead($path)
  try{
   Put "Jumlah entri ZIP: $($zip.Entries.Count)"
   $entries=@($zip.Entries)
   foreach($e in $entries | Select-Object -First 200){Put "  $($e.FullName) ($($e.Length) bytes)"}
   if($entries.Count -gt 200){Put "  ...remaining: $($entries.Count-200)"}
   if($mode -eq "APK"){
    $dex=@($entries | Where-Object {$_.FullName -match "^classes[0-9]*\.dex$"})
    $libs=@($entries | Where-Object {$_.FullName -match "^lib/[^/]+/.+\.so$"})
    Put "DEX count: $($dex.Count); native library count: $($libs.Count)"
    Put "ABIs: $((@($libs | ForEach-Object {$_.FullName.Split('/')[1]} | Select-Object -Unique)) -join ', ')"
    $m=$zip.GetEntry("AndroidManifest.xml")
    if($m){
     $b=ReadEntry $m 1048576
     if($b){
      $strings=PoolStrings $b
      Put "";Put "APK manifest string-pool indicators (may include strings not used as declared permissions):"
      foreach($s in $strings | Where-Object {$_ -match "^(android\.permission\.|android\.accessibilityservice\.|com\.whatsapp|com\.android|.*\.service\..*|.*\.receiver\..*|.*\.provider\..*)" -or $_ -match "(?i)spoof|root|xposed|zygisk|lsposed|fake|device|hook|install"} | Select-Object -Unique -First 180){
       Put "  $s"
      }
     }
    }else{Put "WARNING: AndroidManifest.xml not found"}
    Put ""
    Put "APK libraries (first 80):"
    foreach($e in $libs | Select-Object -First 80){Put "  $($e.FullName)"}
   }else{
    Put "";Put "MODUL metadata, boot scripts and policies (PLAIN TEXT; NEVER EXECUTED):"
    $want=@($entries | Where-Object {$_.FullName -match "(^|/)(module\.prop|service\.sh|post-fs-data\.sh|customize\.sh|action\.sh|boot-completed\.sh|sepolicy\.rule|system\.prop|config\.sh|.*\.conf|.*\.json|.*\.toml)$" -and $_.Length -gt 0} | Select-Object -First 70)
    foreach($e in $want){
     Put "";Put "---------- $($e.FullName) ----------"
     $bytes=ReadEntry $e 65536
     if(-not $bytes){Put "[binary or too big]";continue}
     $str=[Text.Encoding]::UTF8.GetString($bytes)
     $lines=@($str -split "\r?\n")
     foreach($line in $lines | Select-Object -First 170){
      if($line -match "(?i)(password|token|secret|api.?key|private.?key)\s*[:=]\s*\S+"){Put "[REDACTED: potential secret]";continue}
      if($line.Length -gt 400){$line=$line.Substring(0,400)+" [truncated]"}
      Put $line
     }
     if($lines.Count -gt 170){Put "[remaining script lines truncated]"}
    }
   }
  }finally{$zip.Dispose()}
 }catch{Put "READ ERROR: $($_.Exception.Message)"}
}
Put ""
Put "PENTING: Data dalam APK dan modul hanya dibaca offline; tidak ada file HP diubah."
Put "Pemeriksaan ini tidak menjamin bebas malware. Jangan menginstal file berisiko pada HP utama kerja sebelum source dinilai."
$out=Join-Path $dir "LAPORAN_KAREPMU_MODUL.txt"
$r | Out-File -LiteralPath $out -Encoding utf8
Write-Host "BERHASIL: $out"
Start-Process notepad.exe -ArgumentList @($out)
