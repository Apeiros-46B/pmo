use std::cmp::{Ordering, Reverse};

use smallvec::SmallVec;

use crate::{
    auth::{AuthContext, RoleTmpId},
    post::{Collection, Rating},
    util::Comparator,
};

// indexed by Permission::to_usize
pub struct PermissionTable([Box<[Rule]>; Permission::COUNT]);

impl PermissionTable {
    /// check if the given permission is allowed in the given context
    pub fn check(&self, perm: Permission, ctx: &AuthContext) -> bool {
        let rules = &self.0[perm.as_usize()];

        // rules are sorted by priority, highest first
        for rule in rules.iter() {
            // find highest-priority match satisfying all conditions
            if rule.conds.iter().all(|cond| cond.matches(ctx)) {
                return ctx.user_role >= rule.role;
            }
        }

        // implicit deny
        false
    }
}

// {{{ build permissions from config
#[derive(Default)]
pub struct PermissionTableBuilder([Vec<Rule>; Permission::COUNT]);

impl PermissionTableBuilder {
    pub fn register(&mut self, rule: Rule) {
        self.0[rule.perm.as_usize()].push(rule);
    }

    pub fn build(self) -> PermissionTable {
        let mut perms: [Box<[Rule]>; Permission::COUNT] = Default::default();

        for (i, mut vec) in self.0.into_iter().enumerate() {
            // sort descending (strongest to weakest)
            vec.sort_unstable_by(|a, b| b.cmp(a));
            perms[i] = vec.into_boxed_slice();
        }

        PermissionTable(perms)
    }
}
// }}}

// {{{ predicates
#[derive(Clone, Debug)]
pub enum Predicate {
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
pub struct Rule {
    pub perm: Permission,
    pub conds: SmallVec<[Predicate; 4]>,
    pub role: RoleTmpId,
    pub exact: bool,
    pub cfg_ord: u32,
}

impl Ord for Rule {
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

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Rule {}
// }}}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use smallvec::{SmallVec, smallvec};

    use crate::{
        auth::{AuthContext, RoleTmpId},
        post::{Collection, Rating},
        util::Comparator,
    };

    use super::{Permission, PermissionTableBuilder, Rule, Predicate};

    fn mock_ctx(role_val: u16, rating: Rating, owned: bool) -> AuthContext {
        AuthContext {
            post_rating: rating,
            post_owned: owned,
            user_role: RoleTmpId(role_val),
            post_collection: Collection(0),
        }
    }

    // {{{ single-predicate evaluation
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
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Lte,
            rating: Rating::Safe
        };

        assert!(cond_rating.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_rating.matches(&mock_ctx(0, Rating::Questionable, false)));
        assert!(!cond_rating.matches(&mock_ctx(0, Rating::Explicit, false)));
    }

    #[test]
    fn test_predicate_post_collection() {
        let cond_collection0 = Predicate::PostCollection {
            eq: true,
            collection: Collection(0),
        };
        let cond_collection0n = Predicate::PostCollection {
            eq: false,
            collection: Collection(0),
        };
        let cond_collection1 = Predicate::PostCollection {
            eq: true,
            collection: Collection(1),
        };

        assert!(cond_collection0.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_collection0n.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_collection1.matches(&mock_ctx(0, Rating::Safe, false)));
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
        let a = Rule {
            perm: Permission::PostView,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 0,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 1,
        };
        // earlier rule is stronger
        assert_eq!(a.cmp(&b), Ordering::Greater);
    }

    #[test]
    fn test_permission_rule_path_depth() {
        let a = Rule {
            perm: Permission::PostView,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 0,
        };
        let b = Rule {
            perm: Permission::PostEditTag,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 1,
        };
        // post.view is weaker than post.edit.tag even though it comes earlier
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_permission_rule_wildcard() {
        let a = Rule {
            perm: Permission::PostEditTag,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: false,
            cfg_ord: 0,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: SmallVec::new(),
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 1,
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
        let a = Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![owned.clone()],
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 0,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: smallvec![owned, rating],
            role: RoleTmpId(0),
            exact: false,
            cfg_ord: 1,
        };
        // less predicates is weaker even though everything else is stronger
        assert_eq!(a.cmp(&b), Ordering::Less);
    }
    // }}}

    // {{{ permission rule evaluation
    #[test]
    fn test_check_perm_implicit_deny() {
        let mut perms = PermissionTableBuilder::default().build();
        assert!(!perms.check(
            Permission::PostView,
            &mock_ctx(0, Rating::Safe, false),
        ));
    }

    #[test]
    fn test_check_perm_engine_priority() {
        let mut builder = PermissionTableBuilder::default();

        let cond_owned = Predicate::PostOwned(true);
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Eq,
            rating: Rating::Safe,
        };

        // rule A: weakest
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 10,
        });

        // rule B: strongest
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone(), cond_rating.clone()],
            role: RoleTmpId(1),
            exact: true,
            cfg_ord: 0,
        });

        // rule C: >E, <D
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
            role: RoleTmpId(1),
            exact: false,
            cfg_ord: 5,
        });

        // rule D: >C, <B
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
            role: RoleTmpId(0),
            exact: true,
            cfg_ord: 5,
        });

        // rule E: >A, <*
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleTmpId(1),
            exact: true,
            cfg_ord: 5,
        });

        let mut perms = builder.build();

        // expected order of permissions:
        // 0. B (2 cond) -> deny
        // 1. D (1 cond, exact=true) -> allow
        // 2. C (1 cond, exact=false) -> deny
        // 3. E (0 cond, cfg_ord=5) -> deny
        // 4. A (0 cond, cfg_ord=10) -> allow

        // context matches B
        let ctx_all = mock_ctx(0, Rating::Safe, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_all), false);

        // context matches owned=true, fails B, should match D before C
        let ctx_one = mock_ctx(0, Rating::Questionable, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_one), true);

        // no predicates true, fails B+D+C, should match E before A because cfg_ord >
        let ctx_none = mock_ctx(0, Rating::Safe, false);
        assert_eq!(perms.check(Permission::PostView, &ctx_none), false);
    }
    // }}}
}
