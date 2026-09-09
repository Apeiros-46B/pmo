-- kept in sync with the config by the application
CREATE TABLE IF NOT EXISTS roles (
	id VARCHAR(32) PRIMARY KEY,
	display_name VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username VARCHAR(32) UNIQUE NOT NULL,
	display_name VARCHAR(64),
	discord_user_id VARCHAR(20) UNIQUE,
	phc_string TEXT NOT NULL,
	role VARCHAR(32), -- null means default
	settings JSONB,
	creation_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

	CONSTRAINT fk_user_role FOREIGN KEY (role) REFERENCES roles(id)
		ON UPDATE CASCADE
		ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY, -- blake3
	user_id INTEGER NOT NULL,
	creation_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration_date DATETIME NOT NULL,

	CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id)
		ON DELETE CASCADE
);

-- invite tokens that allow new user signup and delegates a role to the new user.
-- users with the user.invite permission can invite other users to register accounts
-- with a role strictly lower than theirs, unless their role is already the default
-- role for registered users, in which case it just gives the new user the default
CREATE TABLE IF NOT EXISTS invites (
	token_hash TEXT PRIMARY KEY, -- blake3
	role VARCHAR(32), -- null means default
	inviter_id INTEGER NOT NULL,
	creation_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration_date DATETIME NOT NULL,

	CONSTRAINT fk_invites_role FOREIGN KEY (role) REFERENCES roles(id)
		ON UPDATE CASCADE
		ON DELETE SET NULL,

	CONSTRAINT fk_invites_inviter_id FOREIGN KEY (inviter_id) REFERENCES users(id)
		ON DELETE CASCADE
);
