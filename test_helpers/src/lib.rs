#[macro_export]
macro_rules! configuration {
    (allowed_capabilities: $allowed_capabilities:expr, required_drop_capabilities: $required_drop_capabilities:expr, default_add_capabilities: $default_add_capabilities:expr) => {
        Settings {
            allowed_capabilities: $allowed_capabilities
                .split(",")
                .map(String::from)
                .filter(|s| !s.is_empty())
                .collect(),
            required_drop_capabilities: $required_drop_capabilities
                .split(",")
                .map(String::from)
                .filter(|s| !s.is_empty())
                .collect(),
            default_add_capabilities: $default_add_capabilities
                .split(",")
                .map(String::from)
                .filter(|s| !s.is_empty())
                .collect(),
        };
    };
}
