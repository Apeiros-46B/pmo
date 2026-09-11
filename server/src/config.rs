// TODO: storage paths should probably not be PathBufs, should be custom string
// format so that we can support stuff like S3 URLs
use std::{collections::{HashMap, HashSet}, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::auth::Role;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub roles: Vec<Role>,
    pub permissions: HashMap<String, String>,

    // optional fields
    #[serde(default)]
    pub collections: HashMap<String, CollectionConfig>,
    #[serde(default)]
    pub libraries: HashMap<String, LibraryConfig>,
}

#[derive(Debug, Deserialize)]
pub struct GeneralConfig {
    pub storage_path: PathBuf,
    pub allow_signups: bool,
}

#[derive(Debug, Deserialize)]
pub struct CollectionConfig {
    pub name: String,

    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub permissions: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct LibraryConfig {
    pub name: String,
    pub path: PathBuf,
    pub collection: Option<String>,

    #[serde(rename = "rescan-seconds")]
    #[serde(default = "default_rescan_seconds")]
    pub rescan_seconds: u64,
}

fn default_rescan_seconds() -> u64 { 600 }

impl Config {
    pub fn read(reader: impl std::io::Read) -> Result<Self> {
        let this: Self = yaml_serde::from_reader(reader)?;
        this.validate().context("config is invalid")?;
        Ok(this)
    }

    fn validate(&self) -> Result<()> {
        // should not validate existence of paths, the storage driver should do that

        let mut uniq_role_ids = HashSet::new();
        let mut collection_ids = HashSet::new();

        validate_roles(&self.roles, &mut uniq_role_ids)
            .context("roles block is invalid")?;

        validate_perms_block_roles(&self.permissions, &uniq_role_ids)
            .context("permissions block is invalid")?;

        validate_collections(&self.collections, &mut collection_ids, &uniq_role_ids)
            .context("collections block is invalid")?;

        validate_libraries(&self.libraries, &collection_ids)
            .context("libraries block is invalid")?;

        Ok(())
    }
}

fn validate_roles<'a>(
    roles: &'a Vec<Role>,
    uniq_role_ids: &mut HashSet<&'a String>,
) -> Result<()> {
    let mut seen_owner_role = false;
    let mut seen_user_role = false;
    let mut seen_guest_role = false;

    for role in roles {
        if !uniq_role_ids.insert(&role.id) {
            bail!("role id '{}' is used for multiple roles", role.id);
        }

        if role.owner {
            if seen_owner_role {
                bail!("more than one owner=true role is defined, one is '{}'", role.id);
            }
            seen_owner_role = true;
        }
        if role.user {
            if seen_user_role {
                bail!("more than one user=true role is defined, one is '{}'", role.id);
            }
            seen_user_role = true;
        }
        if role.guest {
            if seen_guest_role {
                bail!("more than one guest=true role is defined, one is '{}'", role.id);
            }
            seen_guest_role = true;
        }
    }

    Ok(())
}

// keys and predicates are validated in perm table construction, this is just roles
fn validate_perms_block_roles(
    block: &HashMap<String, String>,
    uniq_role_ids: &HashSet<&String>,
) -> Result<()> {
    for (perm, role_id) in block.iter() {
        if !uniq_role_ids.contains(role_id) {
            bail!("permission '{perm}' references nonexistent role '{role_id}'");
        }
    }

    Ok(())
}

fn validate_collections<'a>(
    collections: &'a HashMap<String, CollectionConfig>,
    collection_ids: &mut HashSet<&'a String>,
    uniq_role_ids: &HashSet<&String>,
) -> Result<()> {
    let mut seen_default_collection = false;

    for (id, collection) in collections.iter() {
        // since collections is a yaml mapping and not a list, don't need to deduplicate,
        // this is just for checking references from the libraries block
        collection_ids.insert(id);

        if collection.default {
            if seen_default_collection {
                bail!("more than one default=true collection is defined");
            }
            seen_default_collection = true;
        }

        validate_perms_block_roles(&collection.permissions, &uniq_role_ids)?;
    }

    Ok(())
}

fn validate_libraries(
    libraries: &HashMap<String, LibraryConfig>,
    collection_ids: &HashSet<&String>,
) -> Result<()> {
    for library in libraries.values() {
        let Some(ref collection) = library.collection else { continue };

        if !collection_ids.contains(collection) {
            bail!("nonexistent collection '{collection}'")
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        auth::Role,
        config::{CollectionConfig, Config},
    };

    fn create_valid_config() -> Config {
        let yaml = "
            general:
                storage_path: /mnt/media/pmo
                allow_signups: false
            roles:
                - id: owner
                  name: Owner
                  owner: true
                - id: user
                  name: User
                  user: true
            permissions:
                post.view: owner
            collections:
                col1:
                    name: Primary Collection
                    default: true
                    permissions:
                        post.view: user
            libraries:
                lib1:
                    name: Main Library
                    path: /mnt/media/lib1
                    collection: col1
                    rescan-seconds: 600
        ";
        Config::read(yaml.as_bytes()).expect("creating valid config failed")
    }

    #[test]
    fn test_valid_config_is_ok() {
        let config = create_valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_duplicate_role_ids() {
        let mut config = create_valid_config();
        config.roles.push(Role {
            id: "owner".to_string(),
            name: "Owner".to_string(),
            owner: false,
            user: false,
            guest: false,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_multiple_owner_roles() {
        let mut config = create_valid_config();
        config.roles.push(Role {
            id: "owner2".to_string(),
            name: "Owner 2".to_string(),
            owner: true,
            user: false,
            guest: false,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_multiple_user_roles() {
        let mut config = create_valid_config();
        config.roles.push(Role {
            id: "user2".to_string(),
            name: "User 2".to_string(),
            owner: false,
            user: true,
            guest: false,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_multiple_guest_roles() {
        let mut config = create_valid_config();
        config.roles.push(Role {
            id: "guest1".to_string(),
            name: "Guest".to_string(),
            owner: false,
            user: false,
            guest: true,
        });
        assert!(config.validate().is_ok());

        config.roles.push(Role {
            id: "guest2".to_string(),
            name: "Guest 2".to_string(),
            owner: false,
            user: false,
            guest: true,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_global_permission_nonexistent_role() {
        let mut config = create_valid_config();
        config.permissions.insert(
            "post.edit".to_string(),
            "nonexistent_role".to_string()
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_multiple_default_collections() {
        let mut config = create_valid_config();
        config.collections.insert(
            "col2".to_string(),
            CollectionConfig {
                name: "Secondary Collection".to_string(),
                default: true,
                permissions: HashMap::new(),
            },
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_collection_permission_nonexistent_role() {
        let mut config = create_valid_config();
        let col = config.collections.get_mut("col1").unwrap();
        col.permissions.insert(
            "post.edit".to_string(),
            "nonexistent".to_string()
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_library_references_nonexistent_collection() {
        let mut config = create_valid_config();
        let lib = config.libraries.get_mut("lib1").unwrap();
        lib.collection = Some("col2".to_string());
        assert!(config.validate().is_err());
    }
}
