#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 04 — SQL Injection: UNION-based extraction · Hard · 250 pts
=====================================================================
A product search reflects query rows (3 columns) into the page. The flag lives in a
different table, `secrets`. Find the column count with ORDER BY, then UNION it out:
  ' ORDER BY 3 --       (works)      ' ORDER BY 4 --   (error -> 3 columns)
  ' UNION SELECT flag, NULL, NULL FROM secrets --

Run:  python3 app.py
"""
import os, sys, sqlite3, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "sqli_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "app.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
    con.executemany("INSERT INTO products(name, category, price) VALUES (?,?,?)", [
        ("Laptop Pro 14",       "Computers",   1299.0),
        ("Wireless Mouse",      "Accessories",   24.5),
        ("Mechanical Keyboard", "Accessories",   89.0),
        ("USB-C Hub",           "Accessories",   39.9),
        ("27\" Monitor",        "Displays",     249.0),
        ("Noise-cancel Headset","Audio",        179.0),
    ])
    con.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, flag TEXT)")
    con.execute("INSERT INTO secrets(name, flag) VALUES (?,?)", ("vault", FLAG))
    con.execute("CREATE TABLE credit_cards (ccid INTEGER PRIMARY KEY, ccnumber TEXT, expiration TEXT)")
    con.executemany("INSERT INTO credit_cards(ccnumber, expiration) VALUES (?,?)", [
        ("4444111122223333", "2027-03"), ("7746536337776330", "2028-11")])
    con.commit()
    con.close()


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.search_page(qs.get("q", [None])[0], qs.get("result", [None])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def search_page(self, q, result=None):
        results_html = ""
        if q is not None:
            # ======= VULN HERE =======
            # The search term is concatenated into the SQL, so a quote lets you append your own
            # UNION SELECT and the page prints whatever rows come back.
            # Fix: parameterized query  ("... WHERE name LIKE ?", ('%' + q + '%',))  + a
            #      least-privilege DB user that can't read other tables.
            query = ("SELECT name, category, price FROM products "
                     "WHERE name LIKE '%" + q + "%'")
            # ==========================
            con = sqlite3.connect(DB)
            try:
                rows = con.execute(query).fetchall()
                err = ""
            except sqlite3.Error as e:
                rows, err = [], f"Database error: {e}"
            finally:
                con.close()

            if err:
                results_html = f"<p class='bad'>{html.escape(err)}</p>"
            elif not rows:
                results_html = "<p class='note'>No products found.</p>"
            else:
                trs = ""
                for r in rows:
                    cells = "".join(f"<td>{html.escape('' if v is None else str(v))}</td>" for v in r)
                    trs += f"<tr>{cells}</tr>"
                results_html = f"""
                <table style="width:100%;border-collapse:collapse;margin-top:8px">
                  <tr style="text-align:left;color:var(--muted)"><th>Name</th><th>Category</th><th>Price</th></tr>
                  {trs}
                </table>"""
                if any(FLAG in str(v) for r in rows for v in r):
                    results_html += f"<div class='flag'>🚩 Data from another table leaked: {html.escape(FLAG)}</div>"
            results_html += (f"<p class='note' style='margin-top:14px'>Query that ran:</p>"
                             f"<pre style='white-space:pre-wrap'><code>{html.escape(query)}</code></pre>")

        val = html.escape(q or "", quote=True)
        body = f"""
        <h2>TechShop — Product search</h2>
        <form method="GET" action="/">
          <input name="q" value="{val}" placeholder="e.g. mouse" autocomplete="off">
          <button type="submit">Search</button>
        </form>
        {results_html}"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    init_db()
    common.serve(C, Handler)
