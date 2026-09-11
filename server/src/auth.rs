use std::collections::HashMap;

use moka::future::Cache;
use serde::Deserialize;

/// integer is db primary key
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(usize);

#[derive(Clone)]
pub struct User {
    pub id: UserId,
    pub role: RoleKey,
}

/// not a primary key. role_a > role_b means that role_a is higher
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleKey(pub u16);

impl RoleKey {
    pub fn i(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,

    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub user: bool,
    #[serde(default)]
    pub guest: bool,
}

// TODO: interface for handling user login, cache invalidation, etc
pub struct Auth {
    // indexed by RoleKey, first role is lowest
    pub roles: Vec<Role>,
    pub role_mapping: HashMap<String, RoleKey>,

    // cache of user auth data
    pub user_cache: Cache<UserId, User>,
}

impl Auth {
    /// roles must be sorted by power, the highest role first and the lowest last
    pub fn new(
        user_cache_size: u64,
        roles: Vec<Role>,
    ) -> Self {
        let mut role_mapping = HashMap::new();

        // rev to iterate from lowest to highest, lowest gets role key 0
        for (i, role) in roles.iter().rev().enumerate() {
            role_mapping.insert(role.id.clone(), RoleKey(i as u16));
        }

        Auth {
            roles,
            role_mapping,
            user_cache: Cache::new(user_cache_size),
        }
    }
}
