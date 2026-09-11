use std::{ops::Deref, sync::Arc};

use anyhow::Result;
use smallvec::smallvec;

use crate::{
    auth::{Auth, RoleKey},
    db::Db,
    perms::{Permission, PermissionTableBuilder, Predicate, Rule},
    post::Collection,
    secrets::Secrets,
};

#[derive(Clone)]
pub struct AppState(Arc<State>);

pub struct State {
    pub db: Db,
    pub auth: Auth,
    pub secrets: Secrets
}

impl AppState {
    /// Create a new application state and connect to the database.
    pub async fn new() -> Result<Self> {
        // TODO: pass config table

        let mut perm_builder = PermissionTableBuilder::default();

        perm_builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![
                Predicate::PostCollection {
                    eq: true,
                    collection: Collection(0),
                },
            ],
            role: RoleKey(1),
            exact: true,
        });

        perm_builder.register(Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![Predicate::PostOwned(false)],
            role: RoleKey(2),
            exact: true,
        });
        perm_builder.register(Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![],
            role: RoleKey(1),
            exact: true,
        });

        let perms = perm_builder.build();

        // TODO: don't hardcode database path, derive from config
        let db = Db::open("test.db").await?;
        let auth = Auth::new(64, todo!(), perms);
        let secrets = Secrets::read_or_generate(&db).await?;

        Ok(AppState(Arc::new(State { db, auth, secrets })))
    }
}

impl Deref for AppState {
    type Target = Arc<State>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
