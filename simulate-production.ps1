# Smart Log Analyzer - Production Simulator
# This script continuously generates realistic logs to simulate a production environment

$apiUrl = "http://localhost:5000/logs"

$services = @("payment-service", "auth-service", "user-service", "database-service", "api-gateway", "cache-service")

$errorMessages = @(
    "Payment processing failed - gateway timeout from 10.0.2.15",
    "Database connection pool exhausted - DB_CONN_ERROR",
    "Authentication token expired for user_4523",
    "Cache miss rate exceeding threshold - CACHE_MISS_HIGH",
    "API rate limit exceeded from 192.168.1.100",
    "Service unavailable - circuit breaker open - SVC_UNAVAILABLE",
    "Failed to connect to external API at 52.14.88.210",
    "Invalid request payload - INVALID_PAYLOAD from 172.16.0.45",
    "Session timeout for user_8192",
    "Memory usage critical - MEM_CRITICAL_ERROR"
)

$infoMessages = @(
    "User login successful for user_5021 from 192.168.0.105",
    "Payment processed successfully for user_7834",
    "Cache warmed up - accessed from 10.0.1.20",
    "Health check passed",
    "Request completed from 172.20.10.5",
    "Session created for user_3456",
    "Data synchronized from 10.0.0.50",
    "Backup completed"
)

$warnMessages = @(
    "High latency detected from 192.168.5.100 - LATENCY_WARNING",
    "Cache hit rate below 50% - CACHE_LOW",
    "Slow query detected - SLOW_QUERY_WARN",
    "Memory usage at 75% - MEM_WARNING",
    "Request queue growing from 10.1.1.80"
)

Write-Host "🚀 Starting Production Simulator..." -ForegroundColor Green
Write-Host "Generating logs every 3-10 seconds..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Cyan

$counter = 0

while ($true) {
    $counter++

    # Randomly decide log level (80% INFO, 15% WARN, 5% ERROR)
    $rand = Get-Random -Minimum 1 -Maximum 100

    if ($rand -le 5) {
        $level = "ERROR"
        $message = Get-Random -InputObject $errorMessages
        $service = Get-Random -InputObject $services
        $color = "Red"
    }
    elseif ($rand -le 20) {
        $level = "WARN"
        $message = Get-Random -InputObject $warnMessages
        $service = Get-Random -InputObject $services
        $color = "Yellow"
    }
    else {
        $level = "INFO"
        $message = Get-Random -InputObject $infoMessages
        $service = Get-Random -InputObject $services
        $color = "Green"
    }

    # Add user IDs to some messages
    if ($message -like "*user*" -or $message -like "*Session*") {
        $userId = Get-Random -Minimum 1000 -Maximum 9999
        $message = $message + " (user $userId)"
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    $logBody = @{
        timestamp = $timestamp
        level = $level
        source = $service
        message = $message
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method POST -ContentType "application/json" -Body $logBody -ErrorAction Stop
        Write-Host "[$counter] $level - $service - $message" -ForegroundColor $color

        # If ERROR, occasionally trigger multiple errors from same service
        if ($level -eq "ERROR" -and (Get-Random -Minimum 1 -Maximum 100) -le 30) {
            Write-Host "  ⚠️  Cascading failure detected..." -ForegroundColor Red
            Start-Sleep -Seconds 1

            # Generate 2-3 more errors from same service
            $cascadeCount = Get-Random -Minimum 2 -Maximum 4
            for ($i = 1; $i -le $cascadeCount; $i++) {
                $cascadeMessage = Get-Random -InputObject $errorMessages
                $cascadeBody = @{
                    timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    level = "ERROR"
                    source = $service
                    message = "$cascadeMessage (cascade $i)"
                } | ConvertTo-Json

                Invoke-RestMethod -Uri $apiUrl -Method POST -ContentType "application/json" -Body $cascadeBody -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  -> Cascade ${i}: $cascadeMessage" -ForegroundColor DarkRed
            }
        }
    }
    catch {
        Write-Host "  ✗ Failed to send log: $_" -ForegroundColor DarkRed
    }

    # Random sleep between 3-10 seconds
    $sleepSeconds = Get-Random -Minimum 3 -Maximum 10
    Start-Sleep -Seconds $sleepSeconds
}
