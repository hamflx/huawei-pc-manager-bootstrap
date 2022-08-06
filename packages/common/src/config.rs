use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub product_name: String,
    pub manufacturer: String,
    pub version: String,
    pub sn: String,
    pub sku: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            manufacturer: "HUAWEI".to_string(),
            product_name: "HKD-WXX".to_string(),
            version: "1.0".to_string(),
            sn: "5EKPM18320000397".to_string(),
            sku: "C233".to_string(),
        }
    }
}

pub fn get_project_dir() -> anyhow::Result<ProjectDirs> {
    directories::ProjectDirs::from("cn", "hamflx", "huawei_pc_manager_bootstrap")
        .ok_or_else(|| anyhow::anyhow!("No project dir"))
}

pub fn get_cache_dir() -> anyhow::Result<PathBuf> {
    ensure_dir_exists(get_project_dir()?.cache_dir().to_path_buf())
}

pub fn get_config_dir() -> anyhow::Result<PathBuf> {
    ensure_dir_exists(get_project_dir()?.config_dir().to_path_buf())
}

pub fn get_config_file_path() -> anyhow::Result<PathBuf> {
    let mut config_file_path = get_config_dir()?;
    config_file_path.push("config.json");
    Ok(config_file_path)
}

pub fn ensure_dir_exists(path: PathBuf) -> anyhow::Result<PathBuf> {
    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(path)
}

pub fn get_firmware_config() -> anyhow::Result<Config> {
    let config_file_path = get_config_file_path()?;
    let config_content = std::fs::read_to_string(config_file_path)?;
    let config = serde_json::from_str(config_content.as_str())?;
    Ok(config)
}

pub fn save_firmware_config(config: &Config) -> anyhow::Result<()> {
    let config_file_path = get_config_file_path()?;
    let config_content = serde_json::to_string(config)?;
    std::fs::write(config_file_path, config_content)?;
    Ok(())
}
