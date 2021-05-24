use anyhow::{anyhow, Result};
use k8s_openapi::api::core::v1::{Capabilities, Pod, SecurityContext};
use kubewarden_policy_sdk::request::ValidationRequest;
use std::collections::HashSet;

use crate::settings::Settings;

pub(crate) fn patch_object(
    validation_req: &ValidationRequest<Settings>,
) -> Result<Option<serde_json::Value>> {
    let mut pod: Pod = serde_json::from_value(validation_req.request.object.clone())
        .map_err(|e| anyhow!("Error deserializing Pod specification: {:?}", e))?;
    let mut changed = false;

    if pod.spec.is_none() {
        return Ok(None);
    }
    let mut pod_spec = pod.spec.unwrap();

    for mut c in pod_spec.containers.iter_mut() {
        let sc =
            patch_container_security_context(c.security_context.clone(), &validation_req.settings);
        if sc.is_some() {
            changed = true;
        }
        c.security_context = sc;
    }

    if pod_spec.init_containers.is_some() {
        let mut init_containers = pod_spec.init_containers.clone().unwrap();
        for mut c in init_containers.iter_mut() {
            let sc = patch_container_security_context(
                c.security_context.clone(),
                &validation_req.settings,
            );
            if sc.is_some() {
                changed = true;
            }
            c.security_context = sc;
        }
        pod_spec.init_containers = Some(init_containers);
    }

    pod.spec = Some(pod_spec);

    if changed {
        match serde_json::to_value(pod) {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(anyhow!("Error serializing modified Pod: {:?}", e)),
        }
    } else {
        Ok(None)
    }
}

fn patch_container_security_context(
    security_context: Option<SecurityContext>,
    settings: &Settings,
) -> Option<SecurityContext> {
    let mut changed: bool;

    let mut sc = security_context.unwrap_or(SecurityContext {
        capabilities: Some(Capabilities {
            add: Some(Vec::<String>::new()),
            drop: Some(Vec::<String>::new()),
        }),
        allow_privilege_escalation: None,
        privileged: None,
        proc_mount: None,
        read_only_root_filesystem: None,
        run_as_group: None,
        run_as_non_root: None,
        run_as_user: None,
        se_linux_options: None,
        seccomp_profile: None,
        windows_options: None,
    });

    let mut capabilities = sc.capabilities.unwrap_or_default();

    // Handle add capabilities
    let mut cap_add = capabilities.add.unwrap_or_default();
    let cap_add_size_before = cap_add.len();

    let current_add: HashSet<String> = cap_add.iter().map(|i| i.to_owned()).collect();
    for to_be_added in settings.default_add_capabilities.difference(&current_add) {
        cap_add.push(String::from(to_be_added));
    }
    if cfg!(test) {
        // this code is exectuted only in test mode
        // we need to sort the capabilities to prevent
        // flacky tests
        cap_add.sort();
    }
    changed = cap_add_size_before != cap_add.len();

    capabilities.add = Some(cap_add);

    // Handle add capabilities
    let mut cap_drop = capabilities.drop.unwrap_or_default();
    let cap_drop_size_before = cap_drop.len();

    let current_drop: HashSet<String> = cap_drop.iter().map(String::from).collect();
    for to_be_droped in settings
        .required_drop_capabilities
        .difference(&current_drop)
    {
        cap_drop.push(String::from(to_be_droped));
    }
    if cfg!(test) {
        // this code is exectuted only in test mode
        // we need to sort the capabilities to prevent
        // flacky tests
        cap_drop.sort();
    }
    changed = changed || (cap_drop_size_before != cap_drop.len());
    capabilities.drop = Some(cap_drop);

    sc.capabilities = Some(capabilities);

    if changed {
        Some(sc)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use test_helpers::configuration;

    fn test_mutate(payload: serde_json::Value, expected: serde_json::Value) -> Result<()> {
        let validation_req = ValidationRequest::<Settings>::new(payload.to_string().as_bytes())?;
        let mutated = patch_object(&validation_req)?;

        assert_json_eq!(mutated, expected);

        Ok(())
    }

    #[test]
    fn extend_existing_add_capabilities() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
            required_drop_capabilities: "",
            default_add_capabilities: "SYS_TIME,KILL"
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

        let expected = json!({
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
                              "add": ["KILL", "NET_ADMIN", "SYS_TIME"],
                              "drop": []
                           }
                        }
                    }
               ]
            }
        });

        test_mutate(payload, expected)
    }

    #[test]
    fn extend_existing_drop_capabilities() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
            required_drop_capabilities: "BPF",
            default_add_capabilities: "KILL,SYS_TIME"
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
                                      "drop": ["AUDIT_CONTROL"]
                                   }
                                }
                            }
                       ]
                    }
                }
            }
        });

        let expected = json!({
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
                              "add": ["KILL", "SYS_TIME"],
                              "drop": ["AUDIT_CONTROL", "BPF"]
                           }
                        }
                    }
               ]
            }
        });

        test_mutate(payload, expected)
    }

    #[test]
    fn handle_security_context_does_not_exist() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
            required_drop_capabilities: "BPF",
            default_add_capabilities: "KILL,SYS_TIME"
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
                            }
                       ]
                    }
                }
            }
        });

        let expected = json!({
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
                              "add": ["KILL", "SYS_TIME"],
                              "drop": ["BPF"]
                           }
                        }
                    }
               ]
            }
        });

        test_mutate(payload, expected)
    }

    #[test]
    fn handle_security_context_without_capabilities() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
            required_drop_capabilities: "BPF",
            default_add_capabilities: "KILL,SYS_TIME"
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
                                    "allowPrivilegeEscalation": false
                                }
                            }
                       ]
                    }
                }
            }
        });

        let expected = json!({
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
                           "allowPrivilegeEscalation": false,
                           "capabilities": {
                              "add": ["KILL", "SYS_TIME"],
                              "drop": ["BPF"]
                           }
                        }
                    }
               ]
            }
        });

        test_mutate(payload, expected)
    }

    #[test]
    fn handle_init_containers() -> Result<()> {
        let settings = configuration!(
            allowed_capabilities: "SYS_TIME,KILL",
            required_drop_capabilities: "NET_ADMIN",
            default_add_capabilities: "SYS_TIME,KILL"
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
                                      "add": ["SYS_TIME"]
                                   }
                                }
                            }
                       ],
                       "initContainers": [
                           {
                               "name": "init1",
                               "image": "busybox",
                               "command": ["sleep", "1m"]
                           }
                       ]
                    }
                }
            }
        });

        let expected = json!({
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
                              "add": ["KILL", "SYS_TIME"],
                              "drop": ["NET_ADMIN"]
                           }
                        }
                    }
               ],
               "initContainers": [
                   {
                        "name": "init1",
                        "image": "busybox",
                        "command": ["sleep", "1m"],
                        "securityContext": {
                           "capabilities": {
                              "add": ["KILL", "SYS_TIME"],
                              "drop": ["NET_ADMIN"]
                           }
                        }

                   }
               ]

            }
        });

        test_mutate(payload, expected)
    }
}
