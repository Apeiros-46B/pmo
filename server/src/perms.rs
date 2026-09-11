use std::cmp::Ordering;

use anyhow::{Context, Result, bail};
use smallvec::{SmallVec, smallvec};

use crate::{
    auth::RoleKey,
    post::{Collection, Rating},
    util::Comparator,
};

/// context of an action that requires authorization
#[derive(Debug)]
pub struct AuthContext {
    pub post_rating: Rating,
    pub post_score: i64,
    pub post_owned: bool,
    pub post_collection: Collection,
    pub user_role: RoleKey,
}

// indexed by Permission::to_usize
#[derive(Debug)]
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

    pub fn parse_and_register<'a>(
        &mut self,
        perms: impl Iterator<Item = (&'a String, RoleKey)>,
        collection: Option<Collection>,
    ) -> anyhow::Result<()> {
        let perm_key_regex = regex::regex!(r"^([a-z.]+(?:\.\*)?|\*)(\([^)]+\))?$");

        for (full_key, role) in perms {
            let Some(captures) = perm_key_regex.captures(full_key) else {
                bail!("permission key '{full_key}' is malformed");
            };

            let key = captures.get(1).unwrap().as_str();
            let perms = Permission::from_key(key)?;
            let mut conds = if let Some(cap) = captures.get(2) {
                Predicate::from_str(cap.as_str())?
            } else {
                smallvec![]
            };

            if let Some(collection) = collection {
                conds.push(Predicate::PostCollection(collection));
            }

            let exact = perms.len() == 1;
            for perm in perms {
                self.register(Rule {
                    perm,
                    conds: conds.clone(),
                    role,
                    exact,
                });
            }
        }
        Ok(())
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
    PostScore {
        cmp: Comparator,
        score: i64,
    },
    PostOwned(bool), // whether or not the user owns the post
    // TODO: add more predicate options

    // only internally constructed, user text cannot create it
    PostCollection(Collection),
}

pub type PredicateGroup = SmallVec<[Predicate; 4]>;

impl Predicate {
    /// takes a string like "(owned,rating=safe)"
    pub fn from_str(s: &str) -> Result<PredicateGroup> {
        let mut res = smallvec![];

        for predicate in s[1..s.len()-1].split(",") {
            res.push(Self::from_str_one(predicate)?);
        }

        Ok(res)
    }

    /// takes a string like "owned" or "rating=safe"
    fn from_str_one(s: &str) -> Result<Self> {
        let s = s.trim();

        // order matters, longer operators have to come first
        let comparators = [
            ("<=", Comparator::Lte),
            ("!=", Comparator::Neq),
            (">=", Comparator::Gte),
            ("<",  Comparator::Lt),
            ("=",  Comparator::Eq),
            (">",  Comparator::Gt),
        ];

        // try finding comparators first
        for (op, cmp) in comparators {
            let Some(i) = s.find(op) else { continue };

            let key = s[..i].trim();
            let val = s[i + op.len()..].trim();

            return match key {
                "rating" => {
                    let rating = Rating::from_str(val).context("invalid rating value")?;
                    Ok(Predicate::PostRating { cmp, rating })
                }
                "score" => {
                    let score: i64 = val.parse().context("invalid integer value")?;
                    Ok(Predicate::PostScore { cmp, score })
                }
                _ => anyhow::bail!("unknown comparison predicate '{key}'"),
            };
        }

        // no comparators found so it must be a bool flag
        let (key, is_true) = if let Some(stripped) = s.strip_prefix('!') {
            (stripped.trim(), false)
        } else {
            (s, true)
        };

        match key {
            "owned" => Ok(Predicate::PostOwned(is_true)),
            _ => anyhow::bail!("unknown boolean predicate '{key}'"),
        }
    }

    pub fn matches(&self, ctx: &AuthContext) -> bool {
        match self {
            Predicate::PostRating { cmp, rating } => cmp.cmp(ctx.post_rating, *rating),
            Predicate::PostScore { cmp, score } => cmp.cmp(ctx.post_score, *score),
            Predicate::PostOwned(owned) => ctx.post_owned == *owned,
            Predicate::PostCollection(col) => ctx.post_collection == *col,
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
            pub fn from_key(value: &str) -> Result<Vec<Self>> {
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
    pub conds: PredicateGroup,
    pub role: RoleKey,
    pub exact: bool,
}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = (
            self.conds.len(),
            self.exact, // true > false
            self.perm.path_depth(),
            self.role,
        );
        let b = (
            other.conds.len(),
            other.exact,
            other.perm.path_depth(),
            other.role,
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
    // TODO: don't couple these tests to RoleKey's internal repr
    use std::cmp::Ordering;

    use smallvec::smallvec;

    use crate::{
        auth::{RoleKey},
        post::{Collection, Rating},
        util::Comparator,
    };

    use super::{AuthContext, Permission, PermissionTableBuilder, Rule, Predicate};

    fn mock_ctx(role_val: u16, rating: Rating, owned: bool) -> AuthContext {
        AuthContext {
            post_rating: rating,
            post_score: 0,
            post_owned: owned,
            user_role: RoleKey(role_val),
            post_collection: Collection(0),
        }
    }

    // {{{ single-predicate evaluation
    #[test]
    fn test_predicate_post_rating() {
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Lte,
            rating: Rating::Safe
        };

        assert!(cond_rating.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_rating.matches(&mock_ctx(0, Rating::Risky, false)));
        assert!(!cond_rating.matches(&mock_ctx(0, Rating::Unsafe, false)));
    }

    #[test]
    fn test_predicate_post_score() {
        let cond_score_eq = Predicate::PostScore {
            cmp: Comparator::Eq,
            score: 0,
        };
        let cond_score_gt = Predicate::PostScore {
            cmp: Comparator::Gt,
            score: 0,
        };

        assert!(cond_score_eq.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_score_gt.matches(&mock_ctx(0, Rating::Safe, false)));
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
    fn test_predicate_post_collection() {
        let cond_collection0 = Predicate::PostCollection(Collection(0));
        let cond_collection1 = Predicate::PostCollection(Collection(1));

        assert!(cond_collection0.matches(&mock_ctx(0, Rating::Safe, false)));
        assert!(!cond_collection1.matches(&mock_ctx(0, Rating::Safe, false)));
    }
    // }}}

    // TODO: test predicate construction

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
    fn test_permission_rule_role() {
        let a = Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(1),
            exact: true,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(0),
            exact: true,
        };
        // higher role rule is stronger
        assert_eq!(a.cmp(&b), Ordering::Greater);
    }

    #[test]
    fn test_permission_rule_path_depth() {
        let a = Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(1),
            exact: true,
        };
        let b = Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![],
            role: RoleKey(0),
            exact: true,
        };
        // post.view is weaker than post.edit.tag even though it has a higher role
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_permission_rule_wildcard() {
        let a = Rule {
            perm: Permission::PostEditTag,
            conds: smallvec![],
            role: RoleKey(1),
            exact: false,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(0),
            exact: true,
        };
        // wildcard is weaker even though it has a higher role
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
            role: RoleKey(1),
            exact: true,
        };
        let b = Rule {
            perm: Permission::PostView,
            conds: smallvec![owned, rating],
            role: RoleKey(0),
            exact: false,
        };
        // less predicates is weaker even though everything else is stronger
        assert_eq!(a.cmp(&b), Ordering::Less);
    }
    // }}}

    // {{{ permission rule evaluation
    #[test]
    fn test_check_perm_implicit_deny() {
        let perms = PermissionTableBuilder::default().build();
        assert!(!perms.check(
            Permission::PostView,
            &mock_ctx(0, Rating::Safe, false),
        ));
    }

    #[test]
    fn test_check_perm_engine_priority() {
        let mut builder = PermissionTableBuilder::default();

        // TEST: it would probably be good to test the path depth sorting
        let cond_owned = Predicate::PostOwned(true);
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Eq,
            rating: Rating::Safe,
        };

        // rule A: weakest
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(0),
            exact: true,
        });

        // rule B: strongest
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone(), cond_rating.clone()],
            role: RoleKey(1),
            exact: true,
        });

        // rule C: >E, <D
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
            role: RoleKey(1),
            exact: false,
        });

        // rule D: >C, <B
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![cond_owned.clone()],
            role: RoleKey(0),
            exact: true,
        });

        // rule E: >A, <*
        builder.register(Rule {
            perm: Permission::PostView,
            conds: smallvec![],
            role: RoleKey(1),
            exact: true,
        });

        let perms = builder.build();

        // expected order of permissions:
        //      (conds, exact, depth, role)
        // 0. B (    2   true,     1,    1)
        // 1. D (    1,  true,     1,    0)
        // 2. C (    1, false,     1,    1)
        // 3. E (    0,  true,     1,    1)
        // 4. A (    0,  true,     1,    0)

        // context matches B
        let ctx_all = mock_ctx(0, Rating::Safe, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_all), false);

        // context matches owned=true, fails B, should match D before C
        let ctx_one = mock_ctx(0, Rating::Risky, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_one), true);

        // no predicates true, fails B+D+C, should match E before A because role >
        let ctx_none = mock_ctx(0, Rating::Safe, false);
        assert_eq!(perms.check(Permission::PostView, &ctx_none), false);
    }
    // }}}
}
