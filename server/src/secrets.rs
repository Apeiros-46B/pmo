use anyhow::Result;
use rand::{RngExt, SeedableRng, rngs::{StdRng, SysRng}, seq::SliceRandom};
use sqlx::query;

use crate::db::Db;

#[derive(Debug, PartialEq)]
pub struct Secrets {
    pub media_pepper: [u8; 32],
    pub sqids_alphabet: String,
}

impl Secrets {
    fn gen_alphabet(rng: &mut StdRng) -> String {
        let mut bytes = sqids::DEFAULT_ALPHABET.as_bytes().to_vec();
        bytes.shuffle(rng);
        String::from_utf8(bytes).unwrap()
    }

    /// Return the stored secrets or generate and return new ones if there are none.
    pub async fn read_or_generate(db: &Db) -> Result<Self> {
        let result = query!("SELECT * FROM secrets WHERE id = 1")
            .fetch_optional(&db.r).await?;
        if let Some(row) = result {
            return Ok(Self {
                media_pepper: row.media_pepper.try_into().unwrap(),
                sqids_alphabet: row.sqids_alphabet,
            })
        }

        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let media_pepper: [u8; 32] = rng.random();
        let sqids_alphabet = Self::gen_alphabet(&mut rng);

        query!(
            "
            INSERT INTO secrets (id, media_pepper, sqids_alphabet)
            VALUES (1, ?, ?)
            ON CONFLICT (id) DO NOTHING
            ",
            media_pepper.as_slice(),
            sqids_alphabet
        )
            .execute(&db.w).await?;

        Ok(Self { media_pepper, sqids_alphabet })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use sqlx::{SqlitePool, query};

    use crate::{db::Db, secrets::Secrets};

    #[sqlx::test(migrator = "crate::db::MIGRATOR")]
    async fn test_alphabet(pool: SqlitePool) -> Result<()> {
        let db = Db::test(pool);

        let alphabet = Secrets::read_or_generate(&db).await?.sqids_alphabet;
        assert!(alphabet.is_ascii(), "Sqids alphabet contains non-ASCII");

        let mut chars_exp: Vec<char> = sqids::DEFAULT_ALPHABET.chars().collect();
        let mut chars_got: Vec<char> = alphabet.chars().collect();
        chars_exp.sort_unstable();
        chars_got.sort_unstable();
        assert_eq!(chars_exp, chars_got, "Sqids alphabet was not a shuffle");

        Ok(())
    }

    #[sqlx::test(migrator = "crate::db::MIGRATOR")]
    async fn test_reread(pool: SqlitePool) -> Result<()> {
        let db = Db::test(pool);

        // first call should generate, second call should retrieve
        let a = Secrets::read_or_generate(&db).await?;
        let b = Secrets::read_or_generate(&db).await?;
        assert_eq!(a, b, "Re-read secrets differ");

        query!("DELETE FROM secrets").execute(&db.w).await?;

        // store was dropped, new secrets should differ
        let c = Secrets::read_or_generate(&db).await?;
        assert_ne!(b, c, "New secrets did not differ");

        Ok(())
    }
}
