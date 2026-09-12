use std::{ops::Deref, sync::Arc};

use anyhow::Result;

use crate::{
    auth::Auth,
    config::Config,
    db::Db,
    perms::{PermissionTable, PermissionTableBuilder},
    secrets::Secrets,
};

#[derive(Clone)]
pub struct AppState(Arc<State>);

pub struct State {
    pub db: Db,
    pub auth: Auth,
    pub perms: PermissionTable,
    pub secrets: Secrets
}

impl AppState {
    /// Create a new application state and connect to the database.
    pub async fn new(config: Config) -> Result<Self> {
        // TODO: aggregate collections, needed for collection predicates

        let db = Db::open(&config.general.database_path).await?;
        let secrets = Secrets::read_or_generate(&db).await?;

        let auth = Auth::new(64, config.roles);
        let mapped_perms = config.permissions.iter()
            .map(|(key, role)| (key, auth.role_mapping[role]));

        let mut perm_builder = PermissionTableBuilder::default();
        perm_builder.parse_and_register(mapped_perms, None)?;

        // TODO: per-collection perms, need to register col in StorageBackend first

        let perms = perm_builder.build();

        Ok(AppState(Arc::new(State {
            db,
            auth,
            perms,
            secrets,
        })))
    }
}

impl Deref for AppState {
    type Target = Arc<State>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
