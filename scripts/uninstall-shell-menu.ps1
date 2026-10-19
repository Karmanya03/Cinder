$ErrorActionPreference = 'Stop'
$root = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::CurrentUser,
    [Microsoft.Win32.RegistryView]::Default
)
try {
    foreach ($path in @(
        'Software\Classes\*\shell\Cinder',
        'Software\Classes\Directory\shell\Cinder',
        'Software\Classes\Directory\Background\shell\Cinder'
    )) {
        $root.DeleteSubKeyTree($path, $false)
    }
    Write-Output 'Removed Cinder Explorer menus for the current Windows user.'
} finally {
    $root.Dispose()
}
