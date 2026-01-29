@echo off
setlocal

:: 替换 YOUR_OWN_API_KEY 为你自己的 AbuseIPDB API 密钥
set "API_KEY=d2b5af0b9a6ce9441ebeeaac0aacee03affca3bd1b6cd2027c1cb350c6fa2e53834e25161f6b1994"

curl -G "https://api.abuseipdb.com/api/v2/check-block" ^
  --data-urlencode "network=127.0.0.1/24" ^
  -d "maxAgeInDays=15" ^
  -H "Key: %API_KEY%" ^
  -H "Accept: application/json"

pause