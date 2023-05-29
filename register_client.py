import secrets
import sqlite3

client_name = input("Client Name: ")
client_id = secrets.token_hex(32)
client_secret = secrets.token_hex(32)

con = sqlite3.connect("database.db")
cur = con.cursor()
cur.execute('INSERT INTO clients (client_name, client_id, client_secret) VALUES (?, ?, ?)', (client_name, client_id, client_secret))
con.commit()