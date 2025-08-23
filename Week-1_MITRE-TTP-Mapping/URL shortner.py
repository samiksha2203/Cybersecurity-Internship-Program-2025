from flask import Flask, request, redirect, render_template
import sqlite3, random, string, re

DB_PATH = "url_data.db"
app = Flask(__name__)

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS urls(
            code TEXT PRIMARY KEY,
            long_url TEXT NOT NULL,
            clicks INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    return conn

def new_code(n=6):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=n))

def save_url(long_url):
    # normalize
    if not re.match(r"^https?://", long_url):
        long_url = "http://" + long_url
    conn = get_conn()
    cur = conn.cursor()
    code = new_code()
    while cur.execute("SELECT 1 FROM urls WHERE code=?", (code,)).fetchone():
        code = new_code()
    cur.execute("INSERT INTO urls(code, long_url) VALUES(?, ?)", (code, long_url))
    conn.commit()
    conn.close()
    return code

def resolve(code):
    conn = get_conn()
    cur = conn.cursor()
    row = cur.execute("SELECT long_url FROM urls WHERE code=?", (code,)).fetchone()
    if row:
        cur.execute("UPDATE urls SET clicks = clicks + 1 WHERE code=?", (code,))
        conn.commit()
        conn.close()
        return row[0]
    conn.close()
    return None

@app.route("/", methods=["GET", "POST"])
def index():
    short_url = None
    if request.method == "POST":
        long_url = request.form.get("long_url", "").strip()
        if long_url:
            code = save_url(long_url)
            short_url = request.host_url + code
    return render_template("index.html", short_url=short_url)

@app.route("/<code>")
def go(code):
    url = resolve(code)
    return redirect(url) if url else ("Not found", 404)

if __name__ == "__main__":
    app.run(debug=True)
