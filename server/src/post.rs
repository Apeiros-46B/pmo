#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Rating {
    Safe,
    Questionable,
    Explicit,
}

/// not a primary key, transient derived integer
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Collection(pub u32);
