use std::sync::Arc;

use anyhow::Result;
use rand::{RngExt, SeedableRng, rngs::{StdRng, SysRng}, seq::SliceRandom};
use sqlx::{query, sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions}};

// Arc<AppState> used as axum state
pub type AppState = Arc<State>;

pub struct State {
    pub db: Db,
    pub secrets: Secrets
}

pub async fn init_state() -> Result<AppState> {
    // TODO: don't hardcode database path
    let db = Db::open("test.db").await?;
    let secrets = Secrets::read_or_generate(&db).await?;
    Ok(Arc::new(State { db, secrets }))
}

// separate r/w pools, see https://emschwartz.me/psa-your-sqlite-connection-pool-might-be-ruining-your-write-performance/
pub struct Db {
    pub w: SqlitePool,
    pub r: SqlitePool,
}

impl Db {
    async fn open(path: &str) -> Result<Self> {
        let write_opts = SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let read_opts = write_opts.clone().read_only(true);

        let cpus: usize = std::thread::available_parallelism().map_or(1, Into::into);
        let w = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(write_opts)
            .await?;
        let r = SqlitePoolOptions::new()
            .max_connections(cpus as u32)
            .connect_with(read_opts)
            .await?;

        Ok(Self { w, r })
    }
}

#[derive(Debug)]
pub struct Secrets {
    pub media_pepper: [u8; 32],
    pub sqids_alphabet: String,
}

impl Secrets {
    fn gen_alphabet(rng: &mut StdRng) -> String {
        let mut bytes = sqids::DEFAULT_ALPHABET.as_bytes().to_vec();
        bytes.shuffle(rng);

        // SAFETY: safe because default alphabet is ASCII-only (a-zA-Z0-9)
        unsafe { String::from_utf8_unchecked(bytes) }
    }

    /// Create the secrets table if it does not exist, return the stored secrets,
    /// or generate and return new ones if there are no stored secrets.
    async fn read_or_generate(db: &Db) -> Result<Self> {
        query!("
            CREATE TABLE IF NOT EXISTS secrets (
              id INTEGER PRIMARY KEY CHECK (id = 1),
              media_pepper BLOB NOT NULL CHECK (length(media_pepper) = 32),
              sqids_alphabet TEXT NOT NULL
            );
        ").execute(&db.w).await?;

        let row = query!("SELECT * FROM secrets WHERE id = 1")
            .fetch_optional(&db.r).await?;
        if let Some(row) = row {
            return Ok(Self {
                media_pepper: row.media_pepper.try_into().unwrap(),
                sqids_alphabet: row.sqids_alphabet,
            })
        }

        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let media_pepper: [u8; 32] = rng.random();
        let sqids_alphabet = Self::gen_alphabet(&mut rng);

        query!("
            INSERT INTO secrets (id, media_pepper, sqids_alphabet)
            VALUES (1, $1, $2)
            ON CONFLICT (id) DO NOTHING
        ",
            media_pepper.as_slice(),
            sqids_alphabet
        ).execute(&db.w).await?;

        Ok(Self { media_pepper, sqids_alphabet })
    }
}
