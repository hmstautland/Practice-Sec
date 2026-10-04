#!/usr/bin/env bash
# Attacks on the data layer. Requires: API (+ gateway) + Keycloak + the SQL Server container running, curl, jq, docker.
# Lab only; everything here is read-only.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
DB=${SQL_CONTAINER:-seclab-sql}
SQLCMD="/opt/mssql-tools18/bin/sqlcmd -C -S localhost -h -1 -W -s |"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=dave -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"
search() { $C -H "$H" -G "$API/api/blogs/search" --data-urlencode "q=$1"; }
show()   { jq -r 'if type=="array" then (if length==0 then "(nothing)" else .[] | "  \(.title) | \(.body // "")" end) else "  -> \(.status // "?") \(.title // .)" end' 2>/dev/null || echo "  (unparsable answer)"; }

echo "== 1. UNION injection: dave (an ordinary user) reads other people's phone numbers and addresses (want: nothing)"
search "zzz' UNION SELECT Id,Id,Username,Phone+' | '+Address,GETDATE() FROM Users--" | show

echo "== 2. which database identity does the application use, and is it all-powerful? (want: nothing, never 'sa' / sysadmin=1)"
search "zzz' UNION SELECT 1,1,SUSER_NAME(),CONVERT(char(1),IS_SRVROLEMEMBER('sysadmin')),GETDATE()--" | show   # body = 1: sysadmin
echo "   all server logins, through the same hole:"
search "zzz' UNION SELECT 1,1,name,'login',GETDATE() FROM sys.sql_logins--" | show

echo "== 3. blind inference: a yes/no question answered by the number of rows (want: 0 and 0 - the term is only text)"
for want in 1 0; do printf '   is the app a sysadmin = %s ? rows: ' $want; search "zzz' OR IS_SRVROLEMEMBER('sysadmin')=$want --" | jq 'if type=="array" then length else "error" end'; done

echo "== 4. the committed password (docker-compose.yml, appsettings.json, reset-database.sh): log in to the server as sa (want: Login failed)"
docker exec $DB $SQLCMD -U sa -P 'Passw0rd!Passw0rd' -d SecLab -Q "SET NOCOUNT ON; SELECT Username, Phone, Address FROM Users WHERE Id <= 3" 2>&1 | sed 's/^/   /'

echo "== 5. sa is the key to the whole server: read a file from the server's operating system (want: Login failed again)"
docker exec $DB $SQLCMD -U sa -P 'Passw0rd!Passw0rd' -Q "SET NOCOUNT ON; SELECT TOP 3 value FROM STRING_SPLIT((SELECT BulkColumn FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS f), CHAR(10))" 2>&1 | sed 's/^/   /'

echo "== 6. a copy of the table (backup, replica, a colleague with read access): what is stored in Phone and Address? (want: unreadable ciphertext)"
if [ -f .env ]; then
  set -a; . ./.env; set +a
  docker exec $DB $SQLCMD -U seclab_app -P "$SECLAB_APP_PASSWORD" -d SecLab -Q "SET NOCOUNT ON; SELECT TOP 2 Username, LEFT(Phone,40), LEFT(Address,40) FROM Users" 2>&1 | sed 's/^/   /'
else
  echo "   (no .env yet - section 4 already read the plaintext as sa)"
fi
