// TODO
use std::collections::HashMap;

use moka::future::Cache;

use crate::{perms::PermissionTable, post::{Collection, Rating}};

/// integer is db primary key
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(usize);

/// not a primary key. role_a > role_b means that role_a is higher
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleTmpId(pub u16);

impl RoleTmpId {
    pub fn i(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone)]
pub struct User {
    pub id: UserId,
    pub role: RoleTmpId,
}

#[derive(Debug)]
pub struct AuthContext {
    pub post_rating: Rating,
    pub post_owned: bool,
    pub post_collection: Collection,
    pub user_role: RoleTmpId,
}

// TODO: interface for handling user login, cache invalidation, etc
pub struct Auth {
    perms: PermissionTable,

    // indexed by RoleTmpId, value is db primary key for roles
    role_keys: Vec<String>,
    role_mapping: HashMap<String, RoleTmpId>,

    // cache of user auth data
    user_cache: Cache<UserId, User>,
}

impl Auth {
    /// roles must have the highest role come first and the lowest come last
    pub fn new(
        user_cache_size: u64,
        roles: Vec<String>,
        perms: PermissionTable,
    ) -> Self {
        let mut role_keys = vec![];
        let mut role_mapping = HashMap::new();

        // iterate over roles from lowest to highest. i satisfies RoleTmpId ordering
        for (i, key) in roles.iter().rev().enumerate() {
            role_keys.push(key.clone());
            role_mapping.insert(key.clone(), RoleTmpId(i as u16));
        }

        Auth {
            perms,
            role_keys,
            role_mapping,
            user_cache: Cache::new(user_cache_size),
        }
    }
}
