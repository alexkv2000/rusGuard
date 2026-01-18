# Исправляет все ссылки на сервер во всех файлах
$dir = "C:\Users\alexe\IdeaProjects\SOAP\src\main\resources\wsdl\LNetworkServer"

Get-ChildItem -Path $dir -Filter *.wsdl | ForEach-Object {
    Write-Host "Fixing $_..."
    
    $content = Get-Content $_.FullName -Raw
    
    # Заменяем ВСЕ ссылки на XSD
    $content = $content -replace 'http://scud-1\.gaz\.ru/LNetworkServer/LNetworkService\.svc\?xsd=xsd', 'xsd'
    
    # Заменяем другие возможные формы
    $content = $content -replace 'schemaLocation="http://scud-1\.gaz\.ru[^"]+"', 'schemaLocation=""'
    $content = $content -replace 'location="http://scud-1\.gaz\.ru[^"]+"', 'location=""'
    
    $content | Set-Content $_.FullName -Encoding UTF8
}

Write-Host "Done!" -ForegroundColor Green