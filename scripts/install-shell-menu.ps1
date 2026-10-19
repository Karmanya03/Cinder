[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$GuiPath
)
$ErrorActionPreference = 'Stop'

$exe = (Resolve-Path -LiteralPath $GuiPath).Path
$view = [Microsoft.Win32.RegistryView]::Default
$root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)

function Set-CinderVerb([string]$BasePath, [string]$Name, [string]$Label, [string]$Arguments, [bool]$MultiSelect) {
    $verbPath = "$BasePath\shell\Cinder\ExtendedSubCommandsKey\shell\$Name"
    $verb = $root.CreateSubKey($verbPath)
    try {
        $verb.SetValue('MUIVerb', $Label, [Microsoft.Win32.RegistryValueKind]::String)
        $verb.SetValue('Icon', "`"$exe`",0", [Microsoft.Win32.RegistryValueKind]::String)
        if ($MultiSelect) {
            $verb.SetValue('MultiSelectModel', 'Player', [Microsoft.Win32.RegistryValueKind]::String)
        }
        $command = $verb.CreateSubKey('command')
        try {
            $command.SetValue('', "`"$exe`" $Arguments", [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $command.Dispose()
        }
    } finally {
        $verb.Dispose()
    }
}

function Set-CinderMenuTitle([string]$BasePath, [string]$Label) {
    $menu = $root.CreateSubKey("$BasePath\shell\Cinder")
    try {
        $menu.SetValue('MUIVerb', $Label, [Microsoft.Win32.RegistryValueKind]::String)
        $menu.SetValue('Icon', "`"$exe`",0", [Microsoft.Win32.RegistryValueKind]::String)
    } finally {
        $menu.Dispose()
    }
}

try {
    $fileClass = 'Software\Classes\*'
    Set-CinderMenuTitle $fileClass 'Cinder'
    Set-CinderVerb $fileClass 'Open' 'Open with Cinder' '--shell-open %*' $true
    Set-CinderVerb $fileClass 'Create' 'Add to Cinder archive…' '--shell-create %*' $true
    Set-CinderVerb $fileClass 'Create7z' 'Add to 7z archive…' '--shell-create-7z %*' $true
    Set-CinderVerb $fileClass 'Extract' 'Extract to folders…' '--shell-extract %*' $true
    Set-CinderVerb $fileClass 'ExtractHere' 'Extract here' '--shell-extract-here %*' $true
    Set-CinderVerb $fileClass 'Test' 'Test archive(s)' '--shell-test %*' $true

    $directoryClass = 'Software\Classes\Directory'
    Set-CinderMenuTitle $directoryClass 'Cinder'
    Set-CinderVerb $directoryClass 'Create' 'Add folder to Cinder archive…' '--shell-create %*' $true
    Set-CinderVerb $directoryClass 'Create7z' 'Add folder to 7z archive…' '--shell-create-7z %*' $true

    $backgroundClass = 'Software\Classes\Directory\Background'
    Set-CinderMenuTitle $backgroundClass 'Cinder'
    Set-CinderVerb $backgroundClass 'Create' 'Archive this folder…' '--shell-create %V' $false

    Write-Output "Installed Cinder Explorer menus for the current Windows user. App: $exe"
    Write-Output 'The menus are grouped under Cinder and can be removed with uninstall-shell-menu.ps1.'
} finally {
    $root.Dispose()
}
