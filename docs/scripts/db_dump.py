import sqlite3

c = sqlite3.connect("/data/cptm.db")
c.row_factory = sqlite3.Row
for r in c.execute(
    "select name, output_type, built_in, modified from tools "
    "order by name"
):
    d = dict(r)
    print(f"{d['name']:<20} output_type={d['output_type']:<15} built_in={d['built_in']} modified={d['modified']}")
