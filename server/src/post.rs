#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Rating {
    Safe,
    Risky,
    Unsafe,
}

impl Rating {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "safe" => Ok(Rating::Safe),
            "risky" => Ok(Rating::Risky),
            "unsafe" => Ok(Rating::Unsafe),
            _ => Err(anyhow::anyhow!("unknown rating '{s}'")),
        }
    }
}

/// not a primary key, transient derived integer
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct Collection(pub u32);
