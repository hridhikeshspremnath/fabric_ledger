package attesta.policy_test

import rego.v1

import data.attesta.policy

clean := {
	"flag_cred_access": false, "flag_network": false, "flag_obfuscation": false,
	"flag_install_exec": false, "flag_process_spawn": false, "llm_verdict": "NOT_RUN",
}

test_clean_package_has_no_floor if {
	policy.floor == "ALLOW" with input as clean
}

test_network_alone_is_not_a_floor if {
	policy.floor == "ALLOW" with input as object.union(clean, {"flag_network": true})
}

test_obfuscation_needs_review if {
	policy.floor == "REVIEW" with input as object.union(clean, {"flag_obfuscation": true})
}

test_credentials_plus_network_only_needs_review if {
	policy.floor == "REVIEW" with input as object.union(clean, {"flag_cred_access": true, "flag_network": true})
}

test_strictest_floor_wins if {
	policy.floor == "BLOCK" with input as object.union(clean, {"flag_install_exec": true, "flag_obfuscation": true})
}

test_llm_verdicts if {
	policy.floor == "REVIEW" with input as object.union(clean, {"llm_verdict": "SUSPICIOUS"})
	policy.floor == "BLOCK" with input as object.union(clean, {"llm_verdict": "MALICIOUS"})
	policy.floor == "ALLOW" with input as object.union(clean, {"llm_verdict": "BENIGN"})
}

test_reasons_are_reported if {
	policy.reasons == ["install-time execution", "install-time execution combined with obfuscation", "obfuscated code"] with input as object.union(clean, {"flag_install_exec": true, "flag_obfuscation": true})
}
