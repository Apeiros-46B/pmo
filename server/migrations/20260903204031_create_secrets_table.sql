CREATE TABLE IF NOT EXISTS secrets (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	media_pepper BLOB NOT NULL CHECK (length(media_pepper) = 32),
	sqids_alphabet TEXT NOT NULL
);
