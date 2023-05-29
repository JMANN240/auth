CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    passhash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    client_name TEXT UNIQUE NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    client_secret TEXT UNIQUE NOT NULL
);