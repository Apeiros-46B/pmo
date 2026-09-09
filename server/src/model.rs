use std::{ops::Deref, sync::Arc};

use anyhow::Result;
use smallvec::smallvec;

use crate::{
    auth::{Auth, RoleTmpId}, db::Db, perms::{Permission, PermissionTableBuilder, Predicate::{self, PostOwned}, Rule}, post::Collection, secrets::Secrets, util::Comparator,
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

        // TODO: don't hardcode roles and permissions, derive from config
        let roles = vec![
            "owner".to_owned(),
            "mod".to_owned(),
            "user".to_owned(),
            "guest".to_owned(),
        ];

        let mut perm_builder = PermissionTableBuilder::default();

        perm_builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![
                Predicate::PostCollection {
                    eq: true,
                    collection: Collection(0),
                },
            ],
            role: RoleTmpId(1),
            exact: true,
            cfg_ord: 0,
        });

        perm_builder.register(Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![Predicate::PostOwned(false)],
            role: RoleTmpId(2),
            exact: true,
            cfg_ord: 1,
        });
        perm_builder.register(Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![],
            role: RoleTmpId(1),
            exact: true,
            cfg_ord: 2,
        });

        let perms = perm_builder.build();

        // TODO: don't hardcode database path, derive from config
        let db = Db::open("test.db").await?;
        let auth = Auth::new(64, roles, perms);
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
