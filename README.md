# Kodflix Backend

Express/Node.js backend for Kodflix authentication.

## Features

- `/signup` endpoint (creates user in MySQL database)
- `/login` endpoint (verifies credentials)
- Uses Aiven MySQL connection string stored in environment variables.

## Setup

1. Install dependencies: `npm install` or `yarn`
2. Create a `.env` file with the database URL. **Do not commit this file**. Use your own credentials or the one provided by Aiven:
   ```
   DATABASE_URL=mysql://<username>:<password>@<host>:<port>/<dbname>?ssl-mode=REQUIRED
   ```

   Run the `db.sql` script against the database to create the `users` table before starting the server:
   ```bash
   # with mysql client or from Render console
   mysql -u avnadmin -p -h mysql-394a3a35-shivalilaamdabade-6c18.i.aivencloud.com -P 21072 defaultdb < db.sql
   ```

3. Start server: `npm start` or `yarn start`

## Deployment

Push this repo to GitHub and connect to Render; set the same environment variable in Render's dashboard.
