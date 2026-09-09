#[derive(Clone, Debug)]
#[repr(u8)]
pub enum Comparator {
    Lt,
    Lte,
    Eq,
    Neq,
    Gte,
    Gt,
}

impl Comparator {
    pub fn cmp<T: PartialEq + PartialOrd>(&self, x: T, y: T) -> bool {
        match self {
            Self::Lt => x < y,
            Self::Lte => x <= y,
            Self::Eq => x == y,
            Self::Neq => x != y,
            Self::Gte => x >= y,
            Self::Gt => x > y,
        }
    }
}
