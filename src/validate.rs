use anyhow::{anyhow, Result};
use std::collections::HashSet;

use crate::settings::Settings;

use jsonpath_lib as jsonpath;

use kubewarden_policy_sdk::request::ValidationRequest;

pub(crate) fn validate_added_caps(validation_req: &ValidationRequest<Settings>) -> Result<()> {
    let add_queries = vec![
        "$.spec.containers[*].securityContext.capabilities.add",
        "$.spec.initContainers[*].securityContext.capabilities.add",
    ];
    let cap_add = get_caps(&add_queries, validation_req)?;

    if !validation_req.settings.allow_all_capabilities_enabled() {
        let not_allowed: HashSet<String> = cap_add
            .difference(&validation_req.settings.allowed_capabilities)
            .map(|i| i.to_owned())
            .collect();

        if !not_allowed.is_empty() {
            return Err(anyhow!(
                "PSP capabilities policies doesn't allow these capabilities to be added: {:?}",
                not_allowed
            ));
        }
    }

    // ensure none of the added capabilities are on the "required_drop_capabilities" list
    let must_be_dropped: HashSet<String> = cap_add
        .intersection(&validation_req.settings.required_drop_capabilities)
        .map(|i| i.to_owned())
        .collect();

    if !must_be_dropped.is_empty() {
        return Err(anyhow!(
            "PSP capabilities policies doesn't allow these capabilities to be added because they are on the `required_drop_capabilities` list: {:?}",
            must_be_dropped
        ));
    }

    Ok(())
}

fn get_caps(
    queries: &[&str],
    validation_req: &ValidationRequest<Settings>,
) -> Result<HashSet<String>> {
    let mut selector = jsonpath::selector_as::<HashSet<String>>(&validation_req.request.object);

    let mut caps = HashSet::<String>::new();

    for q in queries.iter() {
        let matches = selector(q)
            .map(|mut m| m.pop().unwrap_or_default())
            .map_err(|e| anyhow!("error searching capabilities with query {}: {:?}", q, e))?;

        caps = caps.union(&matches).map(|i| i.to_owned()).collect();
    }

    Ok(caps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serde_json::json;

    use test_helpers::configuration;

    #[test]
    fn allow_only_container_runtime_default_capabilities() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "",
            required_drop_capabilities: "",
            default_add_capabilities: ""
        );

        let payload = json!({
            "settings": json!(settings),
            "request": {
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                       "name": "security-context-demo-4"
                    },
                    "spec": {
                       "containers": [
                            {
                                "name": "sec-ctx-4",
                                "image": "gcr.io/google-samples/node-hello:1.0",
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["NET_ADMIN", "SYS_TIME"]
                                   }
                                }
                            }
                       ]
                    }
                }
            }
        });

        let validation_req = ValidationRequest::<Settings>::new(payload.to_string().as_bytes())?;
        let validation_result = validate_added_caps(&validation_req);
        assert!(validation_result.is_err());

        let vr = validation_result.unwrap_err().to_string();
        for c in vec!["NET_ADMIN", "SYS_TIME"].iter() {
            assert!(vr.contains(c));
        }

        Ok(())
    }

    #[test]
    fn find_not_allowed_caps_added_to_container() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "SYS_TIME,KILL",
            required_drop_capabilities: "",
            default_add_capabilities: "KILL"
        );

        let payload = json!({
            "settings": json!(settings),
            "request": {
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                       "name": "security-context-demo-4"
                    },
                    "spec": {
                       "containers": [
                            {
                                "name": "sec-ctx-4",
                                "image": "gcr.io/google-samples/node-hello:1.0",
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["NET_ADMIN", "SYS_TIME"]
                                   }
                                }
                            }
                       ]
                    }
                }
            }
        });

        let validation_req = ValidationRequest::<Settings>::new(payload.to_string().as_bytes())?;
        let validation_result = validate_added_caps(&validation_req);
        assert!(validation_result.is_err());
        assert!(validation_result
            .unwrap_err()
            .to_string()
            .contains("NET_ADMIN"));

        Ok(())
    }

    #[test]
    fn find_not_allowed_caps_added_to_init_container() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "SYS_TIME,KILL",
            required_drop_capabilities: "",
            default_add_capabilities: "KILL"
        );

        let payload = json!({
            "settings": json!(settings),
            "request": {
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                       "name": "security-context-demo-4"
                    },
                    "spec": {
                       "containers": [
                            {
                                "name": "sec-ctx-4",
                                "image": "gcr.io/google-samples/node-hello:1.0",
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["NET_ADMIN", "SYS_TIME"]
                                   }
                                }
                            }
                       ],
                       "initContainers": [
                            {
                                "name": "sidecar",
                                "image": "busybox",
                                "command": ["sleep", "1h"],
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["SYS_PTRACE"]
                                   }
                                }
                            }
                       ],
                    }
                }
            }
        });

        let validation_req = ValidationRequest::<Settings>::new(payload.to_string().as_bytes())?;
        let validation_result = validate_added_caps(&validation_req);
        assert!(validation_result.is_err());

        let err_msg = validation_result.unwrap_err().to_string();
        for expected in vec!["SYS_PTRACE", "NET_ADMIN"].iter() {
            assert!(
                err_msg.contains(expected),
                "cannot find {} inside of {}",
                expected,
                err_msg
            );
        }

        Ok(())
    }

    #[test]
    fn find_cap_that_must_be_dropped_inside_of_user_added_caps() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "*",
            required_drop_capabilities: "NET_ADMIN,SYS_PTRACE",
            default_add_capabilities: "KILL"
        );

        let payload = json!({
            "settings": json!(settings),
            "request": {
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                       "name": "security-context-demo-4"
                    },
                    "spec": {
                       "containers": [
                            {
                                "name": "sec-ctx-4",
                                "image": "gcr.io/google-samples/node-hello:1.0",
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["NET_ADMIN", "SYS_TIME"]
                                   }
                                }
                            }
                       ],
                       "initContainers": [
                            {
                                "name": "sidecar",
                                "image": "busybox",
                                "command": ["sleep", "1h"],
                                "securityContext": {
                                   "capabilities": {
                                      "add": ["SYS_PTRACE"]
                                   }
                                }
                            }
                       ],
                    }
                }
            }
        });

        let validation_req = ValidationRequest::<Settings>::new(payload.to_string().as_bytes())?;
        let validation_result = validate_added_caps(&validation_req);
        assert!(validation_result.is_err());

        let err_msg = validation_result.unwrap_err().to_string();
        for expected in vec!["SYS_PTRACE", "NET_ADMIN"].iter() {
            assert!(
                err_msg.contains(expected),
                "cannot find {} inside of {}",
                expected,
                err_msg
            );
        }

        Ok(())
    }
}
