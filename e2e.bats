@test "Accept all capabilities when star in allowed capabilities" {
  run kwctl run  --request-path test_data/req_pod_with_allowed_capabilities_accept.json --settings-json '{"allowed_capabilities": ["*"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]

  run kwctl run  --request-path test_data/req_pod_with_allowed_capabilities_reject.json --settings-json '{"allowed_capabilities": ["*"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject when star in allowed capabilities and capabilities in required_drop_capabilities" {
  run kwctl run  --request-path test_data/req_pod_with_allowed_capabilities_reject.json --settings-json '{"allowed_capabilities": ["*"], "required_drop_capabilities": ["BPF"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":"PSP capabilities policies doesn'\''t allow these capabilities to be added*') -ne 0 ]
 
}
@test "Reject capabilities in required_drop_capabilities" {
  run kwctl run  --request-path test_data/req_pod_with_capabilities_in_required_drop_capabilities.json --settings-json '{"required_drop_capabilities": ["NET_ADMIN"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":"PSP capabilities policies doesn'\''t allow these capabilities to be added*') -ne 0 ]
}


@test "Accept capabilities in allowed capabilities" {
  run kwctl run  --request-path test_data/req_pod_with_allowed_capabilities_accept.json --settings-json '{"allowed_capabilities": ["CHOWN", "KILL"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject capabilities not in allowed capabilities" {
  run kwctl run  --request-path test_data/req_pod_with_allowed_capabilities_reject.json --settings-json '{"allowed_capabilities": ["CHOWN", "KILL"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":"PSP capabilities policies doesn'\''t allow these capabilities to be added*') -ne 0 ]
}

@test "Mutate pods" {
  run kwctl run  --request-path test_data/req_pod_with_mutate_capabilities.json --settings-json '{"allowed_capabilities": ["CHOWN", "KILL"], "required_drop_capabilities":["NET_ADMIN"], "default_add_capabilities":["CHOWN"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
  [ $(expr "$output" : '.*"patchType":"JSONPatch"') -ne 0 ]
}

@test "Mutate deployments" {
  run kwctl run  --request-path test_data/req_pod_with_mutate_capabilities_for_deployment.json --settings-json '{"allowed_capabilities": ["CHOWN", "KILL"], "required_drop_capabilities":["NET_ADMIN"], "default_add_capabilities":["CHOWN"]}' annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
  [ $(expr "$output" : '.*"patchType":"JSONPatch"') -ne 0 ]
}
