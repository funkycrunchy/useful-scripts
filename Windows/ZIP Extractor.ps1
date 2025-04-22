# Replace with your actual values
$username = "PUT_EMAIL_HERE"
$password = "PUT_PASSWORD_HERE"  # Use an App password

# Converting password to a secure string
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

# Defining email details
$smtpServer = "smtp.office365.com"
$smtpPort = 587
$from = $username  # Must match the authenticated account
$to = "chris@computer2cloud.com"
$subject = "SMTP Test"
$body = "Hello World - This test was successful."

# Create the email message
$message = New-Object System.Net.Mail.MailMessage
$message.From = $from
$message.To.Add($to)
$message.Subject = $subject
$message.Body = $body

# Configure SMTP client
$smtp = New-Object Net.Mail.SmtpClient($smtpServer, $smtpPort)
$smtp.EnableSsl = $true
$smtp.Credentials = $cred

# Try sending the message
try {
    $smtp.Send($message)
    Write-Host "✅ Email sent successfully!" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to send email. $_"
}
