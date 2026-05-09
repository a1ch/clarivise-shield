# Clarivise Shield - Microsoft 365 Mail Flow Setup
# Requires: Exchange Online PowerShell module
# Install: Install-Module -Name ExchangeOnlineManagement
#
# Usage:
# .\setup-connector.ps1 -ShieldWebhookUrl "https://xxx.supabase.co/functions/v1/shield-inbound" -ShieldSecret "your-secret"

param(
  [Parameter(Mandatory=$true)]  [string]$ShieldWebhookUrl,
  [Parameter(Mandatory=$true)]  [string]$ShieldSecret,
  [Parameter(Mandatory=$false)] [string]$QuarantineThreshold = "PHISHING"
)

Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
Connect-ExchangeOnline

# Step 1: Create mail flow rule to tag inbound external mail
Write-Host "Creating mail flow rule..." -ForegroundColor Cyan
New-TransportRule -Name "Clarivise Shield - Inbound Analysis" `
  -FromScope NotInOrganization `
  -SentToScope InOrganization `
  -SetHeaderName "X-Shield-Analyze" `
  -SetHeaderValue "true" `
  -Comments "Tags inbound external mail for Clarivise Shield AI analysis"

Write-Host "Mail flow rule created." -ForegroundColor Green

# Step 2: Create journal rule to forward copies to Shield webhook
Write-Host "Creating journal rule to Shield webhook..." -ForegroundColor Cyan
New-JournalRule -Name "Clarivise Shield Journal" `
  -JournalEmailAddress $ShieldWebhookUrl `
  -Scope External `
  -Enabled $true

Write-Host "Journal rule created." -ForegroundColor Green

# Step 3: Create quarantine policy
Write-Host "Creating quarantine policy..." -ForegroundColor Cyan
New-QuarantinePolicy -Name "ClariviseShieldPolicy" `
  -EndUserQuarantinePermissionsValue 0 `
  -ESNEnabled $false

Write-Host "Quarantine policy created." -ForegroundColor Green

Write-Host ""
Write-Host "=== Clarivise Shield Setup Complete ===" -ForegroundColor Green
Write-Host "Webhook URL: $ShieldWebhookUrl" -ForegroundColor White
Write-Host "Quarantine threshold: $QuarantineThreshold" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Add this org to Supabase shield_organizations table with the inbound secret" -ForegroundColor White
Write-Host "2. Deploy the Shield dashboard and add admin users" -ForegroundColor White
Write-Host "3. Run test-webhook.ps1 to verify connectivity" -ForegroundColor White
