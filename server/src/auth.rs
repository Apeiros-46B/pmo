// TODO: permissions is done, still need actual user auth stuff
// TODO: might want to split permissions off into a separate file
use std::{cmp::{Ordering, Reverse}, collections::HashMap};

use moka::future::Cache;
use smallvec::SmallVec;

use crate::{post::{Collection, Rating}, util::Comparator};

// {{{ models
/// integer is db primary key
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(usize);

/// not a primary key. role_a > role_b means that role_a is higher
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleTmpId(u32);

impl RoleTmpId {
    pub fn i(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone)]
pub struct User {
    id: UserId,
    role: RoleTmpId,
}

#[derive(Debug)]
pub struct AuthContext {
    post_rating: Rating,
    post_owned: bool,
    post_collection: Collection,
    user_role: RoleTmpId,
}
// }}}

// TODO: interface for handling user login, cache invalidation, etc
pub struct Auth {
    // indexed by Permission::to_usize
    perm_tbl: [Box<[PermissionRule]>; Permission::COUNT],

    // indexed by RoleTmpId, value is db primary key for roles
    role_keys: Vec<String>,
    roles: HashMap<String, RoleTmpId>,

    // cache of user auth data
    user_cache: Cache<UserId, User>,
}

impl Auth {
    /// check if the given permission is allowed in the given context
    pub fn check_perm(&mut self, perm: Permission, ctx: &AuthContext) -> bool {
        let rules = &self.perm_tbl[perm.as_usize()];

        for rule in rules.iter() {
            if rule.conds.iter().all(|cond| cond.matches(ctx)) {
                return rule.allow;
            }
        }

        // implicit deny
        false
    }
}

// {{{ build roles and permissions from config
pub struct AuthBuilder {
    // TODO: need to support role display name and guest/default/owner flags
    roles: Vec<String>,
    perm_tbl: Box<[Vec<PermissionRule>; Permission::COUNT]>,
}

impl AuthBuilder {
    /// roles must have the highest role come first and the lowest come last
    pub fn with_roles(roles: Vec<String>) -> Self {
        let perm_tbl = vec![vec![]; Permission::COUNT]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        Self { roles, perm_tbl }
    }

    pub fn register_perm(&mut self, perm: Permission, rule: PermissionRule) {
        self.perm_tbl[perm.as_usize()].push(rule);
    }

    pub fn build(self, user_cache_size: u64) -> Auth {
        let mut role_keys = vec![];
        let mut roles = HashMap::new();

        // iterate over roles from lowest to highest. i satisfies RoleTmpId ordering
        for (i, key) in self.roles.iter().rev().enumerate() {
            role_keys.push(key.clone());
            roles.insert(key.clone(), RoleTmpId(i as u32));
        }

        let mut perm_tbl: [Box<[PermissionRule]>; Permission::COUNT] =
            std::array::from_fn(|_| Box::default());

        for (i, mut vec) in self.perm_tbl.into_iter().enumerate() {
            // sort descending (strongest to weakest)
            vec.sort_unstable_by(|a, b| b.cmp(a));
            perm_tbl[i] = vec.into_boxed_slice();
        }

        Auth {
            perm_tbl,
            role_keys,
            roles,
            user_cache: Cache::new(user_cache_size),
        }
    }
}
// }}}

// {{{ predicates
#[derive(Clone, Debug)]
pub enum Predicate {
    UserRole {
        cmp: Comparator,
        role: RoleTmpId,
    },
    PostRating {
        cmp: Comparator,
        rating: Rating,
    },
    PostOwned(bool), // whether or not the user owns the post
    PostCollection {
        // false = neq, true = eq
        eq: bool,
        collection: Collection,
    },
    // TODO: add more predicate options
}

impl Predicate {
    pub fn matches(&self, ctx: &AuthContext) -> bool {
        match self {
            Predicate::UserRole { cmp, role } => cmp.cmp(ctx.user_role, *role),
            Predicate::PostRating { cmp, rating } => cmp.cmp(ctx.post_rating, *rating),
            Predicate::PostOwned(owned) => ctx.post_owned == *owned,
            Predicate::PostCollection { eq, collection } => {
                let matches = ctx.post_collection == *collection;
                if *eq { matches } else { !matches }
            },
        }
    }
}
// }}}

// {{{ permission keys
macro_rules! define_permissions {
    ($($member:ident : $key:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Permission {
            $($member,)*
        }

        impl Permission {
            pub const COUNT: usize = [ $(Self::$member),* ].len();
            pub const MEMBERS: [Self; Self::COUNT] = [ $(Self::$member),* ];

            const fn count_dots(s: &str) -> usize {
                let bytes = s.as_bytes();
                let mut count = 0;
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'.' {
                        count += 1;
                    }
                    i += 1;
                }
                count
            }

            /// (comptime) return the number of dots in the member's string key
            pub const fn path_depth(self) -> usize {
                match self {
                    $(Self::$member => {
                        const DEPTH: usize = Permission::count_dots($key);
                        DEPTH
                    },)*
                }
            }

            /// no string validation done
            pub fn from_key(value: &str) -> anyhow::Result<Vec<Self>> {
                // check wildcard
                if let Some(prefix) = value.strip_suffix('*') {
                    let mut matches = Vec::new();

                    $(
                        if $key.starts_with(prefix) {
                            matches.push(Self::$member);
                        }
                    )*

                    if matches.is_empty() {
                        anyhow::bail!("no permissions matched '{}'", value);
                    }
                    Ok(matches)
                } else {
                    match value {
                        $($key => Ok(vec![Self::$member]),)*
                        _ => anyhow::bail!("unknown permission key '{}'", value),
                    }
                }
            }

            pub fn as_usize(self) -> usize {
                self as usize
            }
        }
    }
}

define_permissions! {
    PostView: "post.view",
    PostEditTag: "post.edit.tag",
    PostDelete: "post.delete",
    PostMoveOut: "post.move.out",
    PostMoveIn: "post.move.in",
}
// }}}

// {{{ permission rules
#[derive(Clone, Debug)]
pub struct PermissionRule {
    pub allow: bool,
    pub exact: bool,
    pub cfg_ord: u32,
    pub perm: Permission,
    pub conds: SmallVec<[Predicate; 4]>,
}

impl Ord for PermissionRule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = (
            self.conds.len(),
            self.exact, // true > false
            self.perm.path_depth(),
            Reverse(self.cfg_ord) // lower config index is stronger
        );
        let b = (
            other.conds.len(),
            other.exact,
            other.perm.path_depth(),
            Reverse(other.cfg_ord)
        );
        a.cmp(&b)
    }
}

impl PartialOrd for PermissionRule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PermissionRule {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PermissionRule {}
// }}}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use smallvec::{SmallVec, smallvec};

    use crate::{post::{Collection, Rating}, util::Comparator};

    use super::{
        AuthBuilder,
        AuthContext,
        Permission,
        PermissionRule,
        Predicate,
        RoleTmpId,
    };

    fn mock_ctx(role_val: u32, rating: Rating, owned: bool) -> AuthContext {
        AuthContext {
            post_rating: rating,
            post_owned: owned,
            user_role: RoleTmpId(role_val),
            post_collection: Collection(0),
        }
    }

    // {{{ single-predicate evaluation
    #[test]
    fn test_predicate_user_role() {
        let cond = Predicate::UserRole {
            cmp: Comparator::Gte,
            role: super::RoleTmpId(2)
        };

        assert!(!cond.matches(&mock_ctx(1, Rating::Safe, false)));
        assert!(cond.matches(&mock_ctx(2, Rating::Safe, false)));
        assert!(cond.matches(&mock_ctx(3, Rating::Safe, false)));
    }

    #[test]
    fn test_predicate_post_owned() {
        let cond_owned = Predicate::PostOwned(true);
        let cond_not_owned = Predicate::PostOwned(false);

        assert!(cond_owned.matches(&mock_ctx(0, Rating::Safe, true)));
        assert!(!cond_owned.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(cond_not_owned.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_not_owned.matches(&mock_ctx(0, Rating::Safe, true)));
    }

    #[test]
    fn test_predicate_post_rating() {
        let pred_rating = Predicate::PostRating {
            cmp: Comparator::Lte,
            rating: Rating::Safe
        };

        assert!(pred_rating.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!pred_rating.matches(&mock_ctx(0, Rating::Questionable, false)));
        assert!(!pred_rating.matches(&mock_ctx(0, Rating::Explicit, false)));
    }
    // }}}

    // {{{ permission construction
    #[test]
    fn test_permission_exact() {
        let res = Permission::from_key("post.view").expect("from_key failed");
        let perm = res.get(0).expect("no permission returned");
        assert_eq!(*perm, Permission::PostView);
    }

    #[test]
    fn test_permission_wildcard() {
        let mut res = Permission::from_key("post.move.*").expect("from_key failed");
        let mut expected = vec![Permission::PostMoveIn, Permission::PostMoveOut];
        res.sort_unstable();
        expected.sort_unstable();
        assert_eq!(res, expected);
    }

    #[test]
    fn test_permission_wildcard_all() {
        let res = Permission::from_key("*").expect("from_key failed");
        assert_eq!(&Permission::MEMBERS, res.as_slice());
    }

    #[test]
    fn test_permission_path_depth() {
        assert_eq!(Permission::PostView.path_depth(), 1);
        assert_eq!(Permission::PostEditTag.path_depth(), 2);
        assert_eq!(Permission::PostMoveIn.path_depth(), 2);
    }
    // }}}

    // {{{ permission rule priority ordering
    #[test]
    fn test_permission_rule_cfg_ord() {
        let a = PermissionRule {
            allow: false,
            exact: true,
            cfg_ord: 0,
            perm: Permission::PostView,
            conds: SmallVec::new(),
        };
        let b = PermissionRule {
            allow: true,
            exact: true,
            cfg_ord: 1,
            perm: Permission::PostView,
            conds: SmallVec::new(),
        };
        // earlier rule is stronger
        assert_eq!(a.cmp(&b), Ordering::Greater);
    }

    #[test]
    fn test_permission_rule_path_depth() {
        let a = PermissionRule {
            allow: false,
            exact: true,
            cfg_ord: 0,
            perm: Permission::PostView,
            conds: SmallVec::new(),
        };
        let b = PermissionRule {
            allow: true,
            exact: true,
            cfg_ord: 1,
            perm: Permission::PostEditTag,
            conds: SmallVec::new(),
        };
        // post.view is weaker than post.edit.tag even though it comes earlier
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_permission_rule_wildcard() {
        let a = PermissionRule {
            allow: false,
            exact: false,
            cfg_ord: 0,
            perm: Permission::PostEditTag,
            conds: SmallVec::new(),
        };
        let b = PermissionRule {
            allow: true,
            exact: true,
            cfg_ord: 1,
            perm: Permission::PostView,
            conds: SmallVec::new(),
        };
        // wildcard is weaker even though it comes earlier
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_permission_rule_conds() {
        let owned = Predicate::PostOwned(true);
        let rating = Predicate::PostRating {
            cmp: Comparator::Lte,
            rating: Rating::Safe,
        };
        let a = PermissionRule {
            allow: false,
            exact: true,
            cfg_ord: 0,
            perm: Permission::PostEditTag,
            conds: smallvec![owned.clone()],
        };
        let b = PermissionRule {
            allow: true,
            exact: false,
            cfg_ord: 1,
            perm: Permission::PostView,
            conds: smallvec![owned, rating],
        };
        // less predicates is weaker even though everything else is stronger
        assert_eq!(a.cmp(&b), Ordering::Less);
    }
    // }}}

    // {{{ permission rule evaluation
    #[test]
    fn test_check_perm_implicit_deny() {
        let builder = AuthBuilder::with_roles(vec!["user".to_string()]);
        let mut auth = builder.build(100);
        assert!(!auth.check_perm(
            Permission::PostView,
            &mock_ctx(0, Rating::Safe, false),
        ));
    }

    #[test]
    fn test_check_perm_engine_priority() {
        let mut builder = AuthBuilder::with_roles(vec!["user".to_string()]);

        let cond_owned = Predicate::PostOwned(true);
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Eq,
            rating: Rating::Safe,
        };

        // rule A: weakest
        builder.register_perm(Permission::PostView, PermissionRule {
            allow: true,
            exact: true,
            cfg_ord: 10,
            perm: Permission::PostView,
            conds: smallvec![],
        });

        // rule B: strongest
        builder.register_perm(Permission::PostView, PermissionRule {
            allow: false,
            exact: true,
            cfg_ord: 0,
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone(), cond_rating.clone()],
        });

        // rule C: >E, <D
        builder.register_perm(Permission::PostView, PermissionRule {
            allow: false,
            exact: false,
            cfg_ord: 5,
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
        });

        // rule D: >C, <B
        builder.register_perm(Permission::PostView, PermissionRule {
            allow: true,
            exact: true,
            cfg_ord: 5,
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
        });

        // rule E: >A, <*
        builder.register_perm(Permission::PostView, PermissionRule {
            allow: false,
            exact: true,
            cfg_ord: 5,
            perm: Permission::PostView,
            conds: smallvec![],
        });

        let mut auth = builder.build(100);

        // expected order of permissions:
        // 0. B (2 cond) -> deny
        // 1. D (1 cond, exact=true) -> allow
        // 2. C (1 cond, exact=false) -> deny
        // 3. E (0 cond, cfg_ord=5) -> deny
        // 4. A (0 cond, cfg_ord=10) -> allow

        // context matches B
        let ctx_all = mock_ctx(0, Rating::Safe, true);
        assert_eq!(auth.check_perm(Permission::PostView, &ctx_all), false);

        // context matches owned=true, fails B, should match D before C
        let ctx_one = mock_ctx(0, Rating::Questionable, true);
        assert_eq!(auth.check_perm(Permission::PostView, &ctx_one), true);

        // no predicates true, fails B+D+C, should match E before A because cfg_ord >
        let ctx_none = mock_ctx(0, Rating::Safe, false);
        assert_eq!(auth.check_perm(Permission::PostView, &ctx_none), false);
    }
    // }}}
}
