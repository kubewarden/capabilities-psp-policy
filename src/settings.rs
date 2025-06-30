use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub(crate) struct Settings {
    #[serde(default)]
    pub allowed_capabilities: HashSet<String>,

    #[serde(default)]
    pub required_drop_capabilities: HashSet<String>,

    #[serde(default)]
    pub default_add_capabilities: HashSet<String>,
}

impl Settings {
    pub fn allow_all_capabilities_enabled(&self) -> bool {
        self.allowed_capabilities.contains(&String::from("*"))
    }
}

impl kubewarden_policy_sdk::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        let denied: HashSet<String> = self
            .allowed_capabilities
            .intersection(&self.required_drop_capabilities)
            .cloned()
            .collect();
        if !denied.is_empty() {
            return Err(format!("These capabilities cannot be allowed because they are also required to be dropped: {denied:?}"));
        }

        let denied: HashSet<String> = self
            .default_add_capabilities
            .intersection(&self.required_drop_capabilities)
            .cloned()
            .collect();
        if !denied.is_empty() {
            return Err(format!("These capabilities cannot be added by default because they are also required to be dropped: {denied:?}"));
        }

        let denied: HashSet<String> = self
            .default_add_capabilities
            .difference(&self.allowed_capabilities)
            .cloned()
            .collect();
        if !denied.is_empty() && !self.allow_all_capabilities_enabled() {
            return Err(format!(
                "These capabilities cannot be added by default because they are not allowed: {denied:?}"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    use kubewarden_policy_sdk::settings::Validatable;
    use test_helpers::configuration;

    #[test]
    fn validate_spots_default_add_capability_not_allowed() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "SYS_TIME,KILL",
            required_drop_capabilities: "",
            default_add_capabilities: "NET_ADMIN,SYS_TIME,KILL"
        );

        assert!(settings.validate().is_err());
        Ok(())
    }

    #[test]
    fn allow_all_capabilities_enabled() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "*",
            required_drop_capabilities: "",
            default_add_capabilities: "NET_ADMIN,SYS_TIME,KILL"
        );

        assert!(settings.allow_all_capabilities_enabled());
        Ok(())
    }

    #[test]
    fn validate_handles_default_add_capabilities_set_to_star() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "*",
            required_drop_capabilities: "",
            default_add_capabilities: "NET_ADMIN,SYS_TIME,KILL"
        );

        assert!(settings.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_handles_spots_default_added_caps_that_are_required_to_be_dropped_too() -> Result<()>
    {
        let settings = configuration!(
            allowed_capabilities: "*",
            required_drop_capabilities: "KILL",
            default_add_capabilities: "NET_ADMIN,SYS_TIME,KILL"
        );

        assert!(settings.validate().is_err());
        Ok(())
    }
}
