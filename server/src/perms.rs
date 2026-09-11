// to find extension points that compiler won't catch when adding new enum members:
// - search "EXT.P" when adding predicates
// - search "EXT.S" when adding scopes
// these can probably be removed once i have a better macro for defining predicates,
// but that can be done later
use std::{cmp::Ordering, fmt::Display};

use anyhow::{Context, Result, bail};
use smallvec::{SmallVec, smallvec};

use crate::{
    auth::RoleKey,
    post::{Collection, Rating},
    util::Comparator,
};

// {{{ (EXT.S) target-object information for authorization of actions
// TODO: should probably decouple, should be defined in corresponding model files
#[derive(Debug)]
pub struct PostContext {
    pub rating: Rating,
    pub score: i64,
    pub owned: bool,
    pub collection: Collection,
}

#[derive(Debug)]
pub struct UserContext {
    pub user_role: RoleKey,
}

#[derive(Debug)]
pub struct TagContext {
}

enum ContextData<'a> {
    Post(&'a PostContext),
    User(&'a UserContext),
    Tag(&'a TagContext),
}

trait ResourceContext {
    const SCOPE: PermissionScope;
    fn as_enum(&self) -> ContextData<'_>;
}

impl ResourceContext for PostContext {
    const SCOPE: PermissionScope = PermissionScope::Post;
    fn as_enum(&self) -> ContextData<'_> { ContextData::Post(self) }
}

impl ResourceContext for UserContext {
    const SCOPE: PermissionScope = PermissionScope::User;
    fn as_enum(&self) -> ContextData<'_> { ContextData::User(self) }
}

impl ResourceContext for TagContext {
    const SCOPE: PermissionScope = PermissionScope::Tag;
    fn as_enum(&self) -> ContextData<'_> { ContextData::Tag(self) }
}
// }}}

// indexed by Permission::to_usize
#[derive(Debug)]
pub struct PermissionTable([Box<[Rule]>; Permission::COUNT]);

impl PermissionTable {
    /// check if the given permission is allowed in the given context
    pub fn check<C: ResourceContext>(
        &self,
        perm: Permission,
        ctx: &C,
        role: RoleKey,
    ) -> bool {
        // make sure correct context type passed for given permission
        debug_assert_eq!(perm.scope(), C::SCOPE);

        let rules = &self.0[perm.as_usize()];
        let ctx_enum = ctx.as_enum();

        // rules are sorted by priority, highest first
        for rule in rules.iter() {
            // find highest-priority match satisfying all conditions
            if rule.conds.iter().all(|cond| cond.matches(&ctx_enum)) {
                return role >= rule.role;
            }
        }

        // implicit deny
        false
    }
}

// {{{ build permissions from config
#[derive(Debug, Default)]
pub struct PermissionTableBuilder([Vec<Rule>; Permission::COUNT]);

impl PermissionTableBuilder {
    fn register(&mut self, rule: Rule) {
        self.0[rule.perm.as_usize()].push(rule);
    }

    pub fn parse_and_register<K: AsRef<str> + Display>(
        &mut self,
        perms: impl Iterator<Item = (K, RoleKey)>,
        collection: Option<Collection>,
    ) -> anyhow::Result<()> {
        let perm_key_regex = regex::regex!(r"^([a-z.]+(?:\.\*)?|\*)(\([^)]+\))?$");

        for (full_key, role) in perms {
            let Some(captures) = perm_key_regex.captures(full_key.as_ref()) else {
                bail!("permission key '{full_key}' is malformed");
            };

            let key = captures.get(1).unwrap().as_str();
            let perms = Permission::from_key(key)?;
            let mut conds: PredicateGroup = smallvec![];

            if let Some(cap) = captures.get(2) {
                let s = cap.as_str();
                for predicate in s[1..s.len()-1].split(",") {
                    conds.push(Predicate::from_str(predicate)?);
                }
            }

            if let Some(collection) = collection {
                conds.push(Predicate::PostCollection(collection));
            }

            let exact = perms.len() == 1;
            for perm in perms {
                for cond in &conds {
                    if !cond.is_valid_in(perm.scope()) {
                        // TODO: cross-scope wildcard produces nonsensical error
                        // messages here. probably need to forbid predicates on
                        // cross-scope wildcards (single star) since scope is always
                        // the first path component
                        bail!(
                            "predicate '{}' cannot be used with permission '{}''",
                            cond.key(),
                            perm,
                        );
                    }
                }

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
// TODO: unified macro to define all predicates and all behaviors all at once,
// similar to define_permissions. probably needs to be a proc macro
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

    // TODO: can probably be reused for pools
    PostOwned(bool), // whether or not the user owns the post
    // TODO: add more predicate options

    // only internally constructed, user text cannot create it
    PostCollection(Collection),
}

pub type PredicateGroup = SmallVec<[Predicate; 4]>;

impl Predicate {
    /// takes a string like "owned" or "rating=safe"
    fn from_str(s: &str) -> Result<Self> {
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
                // EXT.P
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
            // EXT.P
            "owned" => Ok(Predicate::PostOwned(is_true)),
            _ => anyhow::bail!("unknown boolean predicate '{key}'"),
        }
    }

    /// self.is_valid_in(scope) should always be true for the scope of the given
    /// context before calling this
    fn matches(&self, ctx: &ContextData) -> bool {
        match (self, ctx) {
            // EXT.P, EXT.S
            (Self::PostRating { cmp, rating }, ContextData::Post(p)) => {
                cmp.cmp(p.rating, *rating)
            }
            (Self::PostScore { cmp, score }, ContextData::Post(p)) => {
                cmp.cmp(p.score, *score)
            }
            (Self::PostOwned(owned), ContextData::Post(p)) => p.owned == *owned,
            (Self::PostCollection(collection), ContextData::Post(p)) => {
                p.collection == *collection
            }
            _ => {
                debug_assert!(false, "predicate eval against mismatched context");
                false
            }
        }
    }

    fn is_valid_in(&self, scope: PermissionScope) -> bool {
        match (self, scope) {
            // EXT.P, EXT.S
            (Self::PostRating { .. }, PermissionScope::Post) => true,
            (Self::PostScore { .. }, PermissionScope::Post) => true,
            (Self::PostOwned(_), PermissionScope::Post) => true,
            (Self::PostCollection(_), PermissionScope::Post) => true,
            _ => false,
        }
    }

    fn key(&self) -> &str {
        match self {
            Predicate::PostRating { .. } => "rating",
            Predicate::PostScore { .. } => "score",
            Predicate::PostOwned(_) => "owned",
            Predicate::PostCollection(_) => "collection",
        }
    }
}
// }}}

// {{{ permission keys
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionScope {
    Post,
    User,
    Tag,
}

macro_rules! define_permissions {
    ($($scope:ident $(. $rest:ident)*),* $(,)?) => { paste::paste! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Permission {
            $(
                [<$scope $($rest)*>],
            )*
        }

        impl Permission {
            pub const COUNT: usize = [ $(Self::[<$scope $($rest)*>]),* ].len();
            pub const MEMBERS: [Self; Self::COUNT] = [
                $(Self::[<$scope $($rest)*>]),*
            ];

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

            /// return the number of dots in the member's string key
            pub const fn path_depth(self) -> usize {
                match self {
                    $(
                        Self::[<$scope $($rest)*>] => {
                            const DEPTH: usize = Permission::count_dots(
                                concat!(
                                    stringify!([<$scope:lower>])
                                    $(, ".", stringify!([<$rest:lower>]))*
                                )
                            );
                            DEPTH
                        },
                    )*
                }
            }

            pub const fn scope(&self) -> PermissionScope {
                match self {
                    $(
                        Self::[<$scope $($rest)*>] => PermissionScope::$scope,
                    )*
                }
            }

            /// no string validation done
            pub fn from_key(value: &str) -> Result<Vec<Self>> {
                if let Some(prefix) = value.strip_suffix('*') {
                    let mut matches = Vec::new();

                    $(
                        if concat!(stringify!([<$scope:lower>]) $(, ".", stringify!([<$rest:lower>]))*).starts_with(prefix) {
                            matches.push(Self::[<$scope $($rest)*>]);
                        }
                    )*

                    if matches.is_empty() {
                        anyhow::bail!("no permissions matched '{}'", value);
                    }
                    Ok(matches)
                } else {
                    match value {
                        $(
                            concat!(stringify!([<$scope:lower>]) $(, ".", stringify!([<$rest:lower>]))*) => Ok(vec![Self::[<$scope $($rest)*>]]),
                        )*
                        _ => anyhow::bail!("unknown permission key '{}'", value),
                    }
                }
            }

            pub fn as_usize(self) -> usize {
                self as usize
            }
        }

        impl Display for Permission {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
                -> Result<(), std::fmt::Error>
            {
                match self {
                    $(
                        Self::[<$scope $($rest)*>] => write!(f, concat!(stringify!([<$scope:lower>]) $(, ".", stringify!([<$rest:lower>]))*)),
                    )*
                }
            }
        }
    } };
}

define_permissions! {
    Post.View,
    Post.Edit.Tag,
    Post.Delete,
    Post.Move.Out,
    Post.Move.In,

    User.Invite,
    User.Edit.Role,
    User.Mod.Mute,
    User.Mod.Ban,

    Tag.Edit.Name,
    Tag.Implication.Create,
    Tag.Implication.Edit,
    Tag.Implication.Delete,
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
    use std::{cmp::Ordering, collections::HashMap};

    use smallvec::smallvec;

    use crate::{
        auth::RoleKey,
        perms::{PermissionScope, ResourceContext},
        post::{Collection, Rating},
        util::Comparator,
    };

    use super::{Permission, PermissionTableBuilder, PostContext, Rule, Predicate};

    fn mock_post_ctx(rating: Rating, owned: bool) -> PostContext {
        PostContext {
            rating,
            score: 0,
            owned,
            collection: Collection(0),
        }
    }

    // {{{ single-predicate evaluation
    #[test]
    fn test_predicate_post_rating() {
        let cond_rating = Predicate::PostRating {
            cmp: Comparator::Lte,
            rating: Rating::Safe,
        };
        let ctx_safe = mock_post_ctx(Rating::Safe, false);
        let ctx_risky = mock_post_ctx(Rating::Risky, false);
        let ctx_unsafe = mock_post_ctx(Rating::Unsafe, false);

        assert!(cond_rating.matches(&ctx_safe.as_enum()));
        assert!(!cond_rating.matches(&ctx_risky.as_enum()));
        assert!(!cond_rating.matches(&ctx_unsafe.as_enum()));
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
        let ctx = mock_post_ctx(Rating::Safe, false);

        assert!(cond_score_eq.matches(&ctx.as_enum()));
        assert!(!cond_score_gt.matches(&ctx.as_enum()));
    }

    #[test]
    fn test_predicate_post_owned() {
        let cond_owned = Predicate::PostOwned(true);
        let cond_not_owned = Predicate::PostOwned(false);
        let ctx_owned = mock_post_ctx(Rating::Safe, true);
        let ctx_unowned = mock_post_ctx(Rating::Safe, false);

        assert!(cond_owned.matches(&ctx_owned.as_enum()));
        assert!(!cond_owned.matches(&ctx_unowned.as_enum()));
        assert!(cond_not_owned.matches(&ctx_unowned.as_enum()));
        assert!(!cond_not_owned.matches(&ctx_owned.as_enum()));
    }

    #[test]
    fn test_predicate_post_collection() {
        let cond_collection0 = Predicate::PostCollection(Collection(0));
        let cond_collection1 = Predicate::PostCollection(Collection(1));
        let ctx = mock_post_ctx(Rating::Safe, false);

        assert!(cond_collection0.matches(&ctx.as_enum()));
        assert!(!cond_collection1.matches(&ctx.as_enum()));
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

    #[test]
    fn test_permission_scope() {
        assert_eq!(Permission::PostView.scope(), PermissionScope::Post);
        assert_eq!(Permission::UserInvite.scope(), PermissionScope::User);
        assert_eq!(Permission::TagImplicationEdit.scope(), PermissionScope::Tag);
    }

    #[test]
    fn test_permission_construction_success() {
        let mut raw = HashMap::new();
        raw.insert("post.view", 0);
        raw.insert("post.edit.tag", 1);
        raw.insert("post.edit.tag(owned)", 2);

        let iter = raw.iter().map(|(k, v)| (k.to_string(), RoleKey(*v)));
        let mut builder = PermissionTableBuilder::default();
        assert!(builder.parse_and_register(iter, None).is_ok());
    }

    #[test]
    fn test_permission_construction_mismatched_scope() {
        let mut raw = HashMap::new();
        raw.insert("tag.edit.name(score>50)", 3);
        raw.insert("user.invite(owned)", 3);

        let iter = raw.iter().map(|(k, v)| (k.to_string(), RoleKey(*v)));
        let mut builder = PermissionTableBuilder::default();
        assert!(builder.parse_and_register(iter, None).is_err());
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
            &mock_post_ctx(Rating::Safe, false),
            RoleKey(0),
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

        // context matches B
        let ctx_all = mock_post_ctx(Rating::Safe, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_all, RoleKey(0)), false);

        // context matches owned=true, fails B, should match D before C
        let ctx_one = mock_post_ctx(Rating::Risky, true);
        assert_eq!(perms.check(Permission::PostView, &ctx_one, RoleKey(0)), true);

        // no predicates true, fails B+D+C, should match E before A because role >
        let ctx_none = mock_post_ctx(Rating::Safe, false);
        assert_eq!(perms.check(Permission::PostView, &ctx_none, RoleKey(0)), false);
    }
    // }}}
}
