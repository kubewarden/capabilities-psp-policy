use guest::prelude::*;
use k8s_openapi::api::core::v1::PodSpec;
use kubewarden_policy_sdk::{mutate_pod_spec_from_request, wapc_guest as guest};

mod validate;
use validate::validate_added_caps;

mod mutate;
use mutate::patch_object;

mod settings;
use settings::Settings;

use kubewarden_policy_sdk::{
    accept_request, protocol_version_guest, reject_request, request::ValidationRequest,
    validate_settings,
};

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;

    match validate_added_caps(&validation_req) {
        Ok(()) => {
            if let Some(patched_pod_spec) = patch_object(&validation_req)? {
                let pod_spec = serde_json::from_value::<PodSpec>(patched_pod_spec)?;
                mutate_pod_spec_from_request(validation_req, pod_spec)
            } else {
                accept_request()
            }
        }
        Err(val_res) => reject_request(Some(val_res.to_string()), None, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    use kubewarden_policy_sdk::test::Testcase;
    use test_helpers::configuration;

    #[test]
    fn no_mutation_is_done() -> Result<()> {
        // this request has NET_ADMIN and SYS_TIME already added. SYS_PTRACE is
        // already dropped
        let request_file = "test_data/req_pod_with_container_with_capabilities_added.json";
        let request_file_for_deployment =
            "test_data/req_pod_with_container_with_capabilities_added_for_deployment.json";
        let tests = vec![
            Testcase {
                name: String::from("Nothing to add"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME",
                required_drop_capabilities: "SYS_PTRACE",
                default_add_capabilities: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Caps already added"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
                required_drop_capabilities: "",
                default_add_capabilities: "NET_ADMIN,SYS_TIME"),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Caps already added in Deployment"),
                fixture_file: String::from(request_file_for_deployment),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
                required_drop_capabilities: "",
                default_add_capabilities: "NET_ADMIN,SYS_TIME"),
                expected_validation_result: true,
            },
        ];

        for tc in tests.iter() {
            let res = tc.eval(validate)?;
            assert!(
                res.mutated_object.is_none(),
                "Something mutated with test case: {}",
                tc.name,
            );
        }

        Ok(())
    }

    #[test]
    fn do_mutations_when_security_context_does_not_exist() -> Result<()> {
        // this request has NET_ADMIN and SYS_TIME already added to the main container.
        // The sidecar container has no capability added.
        // No capability is dropped by the containers
        let request_file = "test_data/req_pod_without_security_context.json";
        let tests = vec![
            Testcase {
                name: String::from("grow drop capabilities"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME",
                required_drop_capabilities: "SYS_PTRACE",
                default_add_capabilities: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("grow add capabilities"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
                required_drop_capabilities: "",
                default_add_capabilities: "NET_ADMIN,SYS_TIME"),
                expected_validation_result: true,
            },
        ];

        for tc in tests.iter() {
            let res = tc.eval(validate)?;
            assert!(
                res.mutated_object.is_some(),
                "No mutation found with test case: {}",
                tc.name,
            );
            println!("mutated: {:?}", res.mutated_object);
        }

        Ok(())
    }

    #[test]
    fn do_mutations_when_security_context_exists() -> Result<()> {
        // this request has NET_ADMIN and SYS_TIME already added to the main container.
        // The sidecar container has no capability added.
        // No capability is dropped by the containers
        let request_file =
            "test_data/req_pod_with_container_with_capabilities_added_and_sidecar.json";
        let tests = vec![
            Testcase {
                name: String::from("Nothing to add"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME",
                required_drop_capabilities: "SYS_PTRACE",
                default_add_capabilities: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Caps already added"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
                required_drop_capabilities: "",
                default_add_capabilities: "NET_ADMIN,SYS_TIME"),
                expected_validation_result: true,
            },
        ];

        for tc in tests.iter() {
            let res = tc.eval(validate)?;
            assert!(
                res.mutated_object.is_some(),
                "No mutation found with test case: {}",
                tc.name,
            );
        }

        Ok(())
    }

    #[test]
    fn ensure_failure_on_unwrap_does_not_happen_anymore() -> Result<()> {
        // This request was found in production, it caused the policy to
        // panic on unwrap
        let request_file = "test_data/panic.json";
        let tc = Testcase {
            name: String::from("enforce"),
            fixture_file: String::from(request_file),
            settings: configuration!(
                allowed_capabilities: "NET_ADMIN,SYS_TIME,KILL",
                required_drop_capabilities: "",
                default_add_capabilities: "NET_ADMIN,SYS_TIME"),
            expected_validation_result: true,
        };

        let res = tc.eval(validate)?;
        assert!(
            res.mutated_object.is_some(),
            "No mutation found with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
