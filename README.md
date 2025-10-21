# Shopping App Deployment Guide

This guide walks you through running the Flask shopping list app locally and moving your data from the default SQLite file to your Neon PostgreSQL database. The instructions assume no prior experience; follow each step in order and you will be ready to redeploy on Render.

## 1. Clone the repository locally

1. Install [Git](https://git-scm.com/downloads) if it is not already on your computer.
2. Open a terminal (Command Prompt on Windows, Terminal on macOS/Linux).
3. Run the following command, replacing `YOUR-GITHUB-USERNAME` with your GitHub handle:
   ```bash
   git clone https://github.com/YOUR-GITHUB-USERNAME/shopping_app.git
   ```
4. Change into the project directory:
   ```bash
   cd shopping_app
   ```

## 2. Set up a Python environment

1. Install Python 3.11 or later from [python.org](https://www.python.org/downloads/).
2. Create and activate a virtual environment so dependencies stay isolated:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   ```
3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## 3. Run the app locally (uses SQLite)

1. Start the development server:
   ```bash
   flask --app app run --debug
   ```
2. Visit http://127.0.0.1:5000 in a browser. Any data you create is stored in `shopping.db` inside the project folder. This file is what we will migrate to Neon.

## 4. Prepare your Neon PostgreSQL database

1. Sign in to the [Neon dashboard](https://console.neon.tech/).
2. Open the `shopping_app_db` project you already created.
3. Copy the **psql connection string**. It looks like:
   ```
   postgresql://USERNAME:PASSWORD@HOST/neondb?sslmode=require&channel_binding=require
   ```
   Keep this window open—you will paste the URL into both the migration script and Render later.

## 5. Export your existing SQLite data (optional but recommended)

If you have existing users or shopping lists you want to keep, export them from SQLite so we can import them into Neon.

```bash
sqlite3 shopping.db ".mode insert" ".output shopping_dump.sql" ".dump"
```

This creates a backup file called `shopping_dump.sql`. You can keep it as an additional backup even after the migration succeeds.

## 6. Run the migration script

The project includes `migrate_to_postgres.py`, which copies everything from SQLite into PostgreSQL and prepares the auto-incrementing IDs.

1. Make sure your virtual environment is still active.
2. Run the script, pointing it at the Neon connection string (paste the one you copied earlier):
   ```bash
   python migrate_to_postgres.py --destination "postgresql://USERNAME:PASSWORD@HOST/neondb?sslmode=require&channel_binding=require"
   ```
   *If you have stored data in a different SQLite file, add `--source PATH/TO/FILE`.*
3. The script prints how many rows it copied for each table. If the Neon tables already contained data and you want to overwrite them, re-run with the `--force` flag:
   ```bash
   python migrate_to_postgres.py --destination "..." --force
   ```

## 7. Point the app at Neon locally (sanity check)

1. Create a `.env` file in the project root with the following line:
   ```env
   DATABASE_URL="postgresql://USERNAME:PASSWORD@HOST/neondb?sslmode=require&channel_binding=require"
   ```
2. Install python-dotenv (already in requirements) and restart the server:
   ```bash
   flask --app app run --debug
   ```
3. Confirm the data you expect is present. If something is missing, re-run the migration or restore the SQLite backup.

## 8. Update Render environment variables

1. Go to the Render dashboard for your web service.
2. Open **Environment → Secret Files & Environment Variables**.
3. Add a new **Secret** called `NEON_DATABASE_URL` and paste the same connection string.
4. In the service’s environment variables, set:
   * **Key:** `DATABASE_URL`
   * **Value:** `{{NEON_DATABASE_URL}}` (Render lets you reference secrets this way) — or manually paste the URL if you prefer.
5. Click **Save Changes** and redeploy/restart the service.

## 9. Verify the production deployment

1. Watch the Render logs during redeploy. You should see messages about connecting to PostgreSQL (no errors about SQLite).
2. Open your live app and run through a quick test: log in, create/update a list, check items. Everything should persist even after Render hibernates because Neon now stores the data.

## 10. Keep your credentials safe

* Treat the Neon connection string like a password. Do **not** commit it to Git or share it publicly.
* If you suspect it was exposed, rotate the password in Neon and update the environment variables.

---

By following these steps, you migrate from a local SQLite database to a persistent Neon PostgreSQL instance and keep both local and deployed versions of the app in sync.
