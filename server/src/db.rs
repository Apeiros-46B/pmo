use anyhow::Result;
use sqlx::{
    sqlite::{
        SqliteConnectOptions,
        SqliteJournalMode,
        SqlitePool,
        SqlitePoolOptions,
    },
};

// https://kobzol.github.io/rust/2026/06/21/optimizing-sqlx-test-rebuild-time.html
#[allow(dead_code)]
pub const MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// SQLite connection with separate read/write pools.
/// https://emschwartz.me/psa-your-sqlite-connection-pool-might-be-ruining-your-write-performance/
pub struct Db {
    pub r: SqlitePool,
    pub w: SqlitePool,
}

impl Db {
    /// Open the SQLite database at the given path and run migrations, if any
    pub async fn open(path: &str) -> Result<Self> {
        let write_opts = SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(SqliteJournalMode::Wal);
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

        sqlx::migrate!().run(&w).await?;

        Ok(Self { r, w })
    }

    /// Create a dummy Db instance with only the given pool. Intended for testing
    #[cfg(test)]
    pub fn test(pool: SqlitePool) -> Self {
        Self {
            r: pool.clone(),
            w: pool,
        }
    }
}
