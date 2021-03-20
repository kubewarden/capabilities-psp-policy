extern crate wapc_guest as guest;
use guest::prelude::*;

mod validate;
use validate::validate_added_caps;

mod mutate;
use mutate::patch_object;

mod settings;
use settings::Settings;

use chimera_kube_policy_sdk::{
    accept_request, reject_request, request::ValidationRequest, validate_settings,
};

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;

    match validate_added_caps(&validation_req) {
        Ok(()) => accept_request(patch_object(&validation_req)?),
        Err(val_res) => reject_request(Some(val_res.to_string()), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    use chimera_kube_policy_sdk::test::Testcase;
    use test_helpers::configuration;

    #[test]
    fn no_mutation_is_done() -> Result<()> {
        // this request has NET_ADMIN and SYS_TIME already added. SYS_PTRACE is
        // already dropped
        let request_file = "test_data/req_pod_with_container_with_capabilities_added.json";
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
                res.mutated_object.is_none(),
                "Something mutated with test case: {}",
                tc.name,
            );
        }

        Ok(())
    }

    #[test]
    fn do_mutations() -> Result<()> {
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
}
