# Clarivise Shield - Test Webhook
# Sends a sample email payload to verify the shield-inbound function is reachable
#
# Usage:
# .\test-webhook.ps1 -WebhookUrl "https://xxx.supabase.co/functions/v1/shield-inbound" -ShieldSecret "your-secret"

param(
  [Parameter(Mandatory=$true)] [string]$WebhookUrl,
  [Parameter(Mandatory=$true)] [string]$ShieldSecret
)

$testPayload = @{
  messageId         = "test-$(Get-Random)"
  internetMessageId = "<test@clarivise.test>"
  subject           = "Test Email - Clarivise Shield Connectivity Check"
  sender            = "test@external-domain.com"
  recipient         = "admin@yourcompany.com"
  body              = "This is a test email to verify Clarivise Shield is working correctly. Please ignore."
  links             = @()
  attachments       = @()
  replyTo           = "test@external-domain.com"
  isExternal        = $true
  receivedAt        = (Get-Date -Format "o")
} | ConvertTo-Json

Write-Host "Sending test payload to Shield webhook..." -ForegroundColor Cyan

try {
  $response = Invoke-RestMethod `
    -Uri $WebhookUrl `
    -Method Post `
    -Headers @{ "x-shield-secret" = $ShieldSecret; "Content-Type" = "application/json" } `
    -Body $testPayload

  Write-Host "Success!" -ForegroundColor Green
  Write-Host "Verdict  : $($response.verdict)"  -ForegroundColor White
  Write-Host "Action   : $($response.action)"   -ForegroundColor White
  Write-Host "Summary  : $($response.summary)"  -ForegroundColor White
} catch {
  Write-Host "Failed: $_" -ForegroundColor Red
  Write-Host "Check that your ShieldSecret matches the inbound_webhook_secret in shield_organizations." -ForegroundColor Yellow
}
