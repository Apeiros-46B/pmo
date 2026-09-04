use std::{ops::Deref, sync::Arc};

use anyhow::Result;

use crate::{db::Db, secrets::Secrets};

#[derive(Clone)]
pub struct AppState(Arc<State>);

pub struct State {
    pub db: Db,
    pub secrets: Secrets
}

impl AppState {
    /// Create a new application state and connect to the database.
    pub async fn new() -> Result<Self> {
        // TODO: pass in config table, don't hardcode database path
        let db = Db::open("test.db").await?;
        let secrets = Secrets::read_or_generate(&db).await?;
        Ok(AppState(Arc::new(State { db, secrets })))
    }
}

impl Deref for AppState {
    type Target = Arc<State>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
