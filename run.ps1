# Script di Avvio Portale PKI Web Enrollment
$env:PATH = "C:\Program Files\dotnet;$env:PATH"
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "   Enterprise PKI Web Enrollment Gateway (AD CS Modern)  " -ForegroundColor White
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "Avvio portale su http://127.0.0.1:5055 ... (Premi Ctrl+C per arrestare)" -ForegroundColor Yellow
Start-Process "http://127.0.0.1:5055"
dotnet run --urls "http://127.0.0.1:5055"
