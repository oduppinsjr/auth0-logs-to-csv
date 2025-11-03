# Auth0 Logs to CSV

Small tool to export your Auth0 Logs to a CSV file.

> Updated to use Auth0 Management API v2

## Getting your account information

 1. Go to the Auth0 dashboard
 2. Go to **Applications** → **Applications** (Machine to Machine Applications)
 3. Create a new Machine to Machine application (or use an existing one)
 4. Authorize it for the "Auth0 Management API" and grant it the `read:logs` scope
 5. Get the `domain`, `client_id` and `client_secret` for your Machine to Machine application
 6. Save this information in the config.json file:
   ```json
   {
     "AUTH0_DOMAIN": "your-domain.auth0.com",
     "AUTH0_CLIENT_ID": "your-client-id",
     "AUTH0_CLIENT_SECRET": "your-client-secret"
   }
   ```

## Exporting your logs

 1. Install Node.js 14.0 or higher: https://nodejs.org/en/download/
 2. Clone/Download this repository
 3. Run `npm start` from the repository's directory

After a few seconds a CSV file will be available containing all of your logs. The CSV includes:
- **timestamp**: ISO formatted timestamp
- **type**: Human-readable event type (e.g., "Success Login", "Failed Login")
- **type_code**: Original Auth0 event type code
- **username**: User's username
- **user_id**: User's unique ID
- **user_name**: User's display name
- **description**: Event description
- **ip**: IP address
- **user_agent**: User agent string
- **client_id**: Client ID
- **client_name**: Client name
- **connection**: Connection name
- **connection_id**: Connection ID
- **details**: Additional details (JSON stringified)
- **log_id**: Log entry ID
- **location_info**: Location information
- **is_mobile**: Mobile device indicator

Use Excel to open the file, use the Text-to-Columns feature (with TAB as a delimiter) and convert everything to a table. This will allow you to filter data, hide columns, ...
