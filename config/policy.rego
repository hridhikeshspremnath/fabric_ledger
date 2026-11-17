# Evidence floors. The score bands (config/policy.yaml) give the base decision; these
# rules can only make it STRICTER, never weaker: `floor` is the least strict decision
# the evidence allows. The effective decision is max(band decision, floor).
#
# input = the unsigned TrustRecord fields (flag_*, llm_verdict, ...).
# Query: POST /v1/data/attesta/policy/floor
package attesta.policy

import rego.v1

default floor := "ALLOW"

# Strictness order, least to most.
rank := {"ALLOW": 0, "WARN": 1, "REVIEW": 2, "BLOCK": 3}

# Every floor that applies, with the reason; the strictest wins.
# BLOCK is reserved for combinations that are hard to explain innocently. Credential
# access plus network use alone only reaches REVIEW: twine, paramiko and similar
# legitimate libraries do both, and the flags are rule-based, so they over-fire.
floors contains {"decision": "BLOCK", "reason": "install-time execution combined with obfuscation"} if {
	input.flag_install_exec
	input.flag_obfuscation
}

floors contains {"decision": "BLOCK", "reason": "LLM review judged the package malicious"} if input.llm_verdict == "MALICIOUS"

floors contains {"decision": "REVIEW", "reason": "credential access"} if input.flag_cred_access

floors contains {"decision": "REVIEW", "reason": "obfuscated code"} if input.flag_obfuscation

floors contains {"decision": "REVIEW", "reason": "install-time execution"} if input.flag_install_exec

floors contains {"decision": "REVIEW", "reason": "LLM review found the package suspicious"} if input.llm_verdict == "SUSPICIOUS"

floor := d if {
	count(floors) > 0
	d := [f.decision | some f in floors][_]
	every f in floors {
		rank[f.decision] <= rank[d]
	}
}

reasons := sort([f.reason | some f in floors])
