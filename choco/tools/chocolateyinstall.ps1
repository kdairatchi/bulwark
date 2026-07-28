$ErrorActionPreference = 'Stop'

$version = '1.4.8'

$packageArgs = @{
  packageName    = 'bulwark'
  fileType       = 'exe'
  url64bit       = "https://github.com/kdairatchi/bulwark/releases/download/v$version/Bulwrk-Setup-$version.exe"
  silentArgs     = '/S'
  validExitCodes = @(0)
  checksum64     = '__REPLACE_WITH_SHA256_HASH__'
  checksumType64 = 'sha256'
}

Install-ChocolateyPackage @packageArgs
