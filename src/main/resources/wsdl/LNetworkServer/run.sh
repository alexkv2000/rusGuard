$folderPath = "src/main/resources/wsdl/LNetworkServer"
Write-Host "Поиск XSD-файлов в: $folderPath"

Get-ChildItem -Path $folderPath -Filter *.xsd | ForEach-Object {
    $file = $_.FullName
    $content = Get-Content $file -Raw
    
    if ($content -match "/java/") {
        $newContent = $content -replace "/java/", "/resources/"
        Set-Content -Path $file -Value $newContent -NoNewline
        Write-Host "✓ Исправлен: $($_.Name)" -ForegroundColor Green
    } else {
        Write-Host "  Пропущен: $($_.Name) (нет /java/)" -ForegroundColor Gray
    }
}

Write-Host "`nГотово! Все XSD-файлы проверены." -ForegroundColor Cyan