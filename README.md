# ZAD OSINT Video Portal

Local run:  pip install -r requirements.txt && ADMIN_USER=admin ADMIN_PASS=yourpass python app.py
Admin:      /admin/login

Render env vars: DATABASE_URL (Neon/Supabase Postgres), SECRET_KEY, ADMIN_USER, ADMIN_PASS, PYTHON_VERSION=3.11.9.
Check after deploy: open /healthz -> should print 'ok postgres'.
Start command: gunicorn app:app --worker-class gthread --workers 1 --threads 8 --timeout 120
Data: SQLite file. Free Render disk is wiped on redeploy -> attach a Disk and set DB_PATH=/var/data/data.db.
