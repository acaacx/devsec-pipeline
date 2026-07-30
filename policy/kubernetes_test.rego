# Unit tests for policy/kubernetes.rego, run by `conftest verify`.
#
# A policy that never fires is worse than no policy: it produces a green check
# that means nothing. Conftest passing against deploy/k8s only proves the
# manifests are not rejected - it does not prove any rule can reject anything.
# Each test below starts from a compliant Deployment and breaks exactly one
# thing, so a rule that stops working fails a test instead of silently passing
# everything forever.
package main

import rego.v1

# A Deployment that satisfies every rule in kubernetes.rego. Kept minimal - only
# the fields the policy actually reads - so a test failure points at the rule
# rather than at incidental manifest detail.
compliant_deployment := {
	"kind": "Deployment",
	"metadata": {"name": "pygoat"},
	"spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"securityContext": {
			"runAsNonRoot": true,
			"runAsUser": 10001,
		},
		"containers": [{
			"name": "pygoat",
			"image": "ghcr.io/acaacx/devsec-pipeline:de6ef896b2dced7e641783223a9b42a9f7b3945c",
			"securityContext": {
				"runAsNonRoot": true,
				"allowPrivilegeEscalation": false,
				"readOnlyRootFilesystem": true,
				"capabilities": {"drop": ["ALL"]},
			},
			"resources": {"limits": {
				"cpu": "1",
				"memory": "1Gi",
			}},
		}],
		"volumes": [{
			"name": "tmp",
			"emptyDir": {},
		}],
	}}},
}

# The baseline. If this ever fails, every other test below is meaningless because
# the fixture itself is being rejected for an unrelated reason.
test_compliant_deployment_produces_no_denials if {
	count(deny) == 0 with input as compliant_deployment
}

# --- image tags -------------------------------------------------------------

test_latest_tag_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "ghcr.io/acaacx/devsec-pipeline:latest",
	}])
	some m in msgs
	contains(m, "':latest'")
}

test_untagged_image_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "ghcr.io/acaacx/devsec-pipeline",
	}])
	some m in msgs
	contains(m, "has no tag")
}

test_digest_pinned_image_is_allowed if {
	count(deny) == 0 with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "ghcr.io/acaacx/devsec-pipeline@sha256:c64ffb6d6fc8087c896341a2c697770a04a1cf558db04fa7b8129d8ca6bce336",
	}])
}

# A registry with a port puts a colon in a non-final path segment. A naive tag
# parser reads "5000/devsec-pipeline" as the tag and fires nothing at all.
test_registry_port_is_not_mistaken_for_a_tag if {
	count(deny) == 0 with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "registry.internal:5000/devsec-pipeline:v1.2.3",
	}])
}

test_latest_tag_behind_a_registry_port_is_still_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "registry.internal:5000/devsec-pipeline:latest",
	}])
	some m in msgs
	contains(m, "':latest'")
}

# --- privilege --------------------------------------------------------------

test_privileged_container_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/containers/0/securityContext/privileged",
		"value": true,
	}])
	some m in msgs
	contains(m, "is privileged")
}

test_missing_allow_privilege_escalation_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
	}])
	some m in msgs
	contains(m, "allowPrivilegeEscalation")
}

test_allow_privilege_escalation_true_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
		"value": true,
	}])
	some m in msgs
	contains(m, "allowPrivilegeEscalation")
}

# --- non-root ---------------------------------------------------------------

test_container_without_non_root_anywhere_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [
		{
			"op": "remove",
			"path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
		},
		{
			"op": "remove",
			"path": "/spec/template/spec/securityContext/runAsNonRoot",
		},
	])
	some m in msgs
	contains(m, "must run as non-root")
}

# The container omits runAsNonRoot but the pod sets it. This must pass, or the
# rule would force redundant duplication on every container in every manifest.
test_pod_level_non_root_is_inherited if {
	count(deny) == 0 with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
	}])
}

# The container explicitly opts out while the pod says otherwise. The container
# value wins at runtime, so the policy must not let the pod-level setting mask it.
test_container_false_overrides_pod_true if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
		"value": false,
	}])
	some m in msgs
	contains(m, "must run as non-root")
}

test_container_run_as_user_zero_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/containers/0/securityContext/runAsUser",
		"value": 0,
	}])
	some m in msgs
	contains(m, "runAsUser: 0")
}

test_pod_run_as_user_zero_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/securityContext/runAsUser",
		"value": 0,
	}])
	some m in msgs
	contains(m, "pod sets runAsUser: 0")
}

# --- filesystem and capabilities -------------------------------------------

test_writable_root_filesystem_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
		"value": false,
	}])
	some m in msgs
	contains(m, "readOnlyRootFilesystem")
}

# The omission case, not just the explicit-false case. This is the same shape of
# bug the allowPrivilegeEscalation test exposed: an absent field made the
# comparison undefined and the rule passed silently.
test_omitted_read_only_root_filesystem_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
	}])
	some m in msgs
	contains(m, "readOnlyRootFilesystem")
}

test_omitted_capabilities_block_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext/capabilities",
	}])
	some m in msgs
	contains(m, "must drop all capabilities")
}

test_omitted_security_context_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext",
	}])
	count(msgs) >= 3
}

test_capabilities_not_dropped_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/securityContext/capabilities/drop",
		"value": ["NET_RAW"],
	}])
	some m in msgs
	contains(m, "must drop all capabilities")
}

test_added_capability_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/containers/0/securityContext/capabilities/add",
		"value": ["NET_ADMIN"],
	}])
	some m in msgs
	contains(m, "NET_ADMIN")
}

# --- resource limits --------------------------------------------------------

test_missing_cpu_limit_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/resources/limits/cpu",
	}])
	some m in msgs
	contains(m, "no cpu limit")
}

test_missing_memory_limit_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/resources/limits/memory",
	}])
	some m in msgs
	contains(m, "no memory limit")
}

test_missing_resources_entirely_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/resources",
	}])
	count([m | some m in msgs; contains(m, "limit")]) == 2
}

# --- host namespaces and host paths ----------------------------------------

test_host_network_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/hostNetwork",
		"value": true,
	}])
	some m in msgs
	contains(m, "hostNetwork")
}

test_host_pid_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/hostPID",
		"value": true,
	}])
	some m in msgs
	contains(m, "hostPID")
}

test_host_path_volume_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/volumes/-",
		"value": {
			"name": "docker-socket",
			"hostPath": {"path": "/var/run/docker.sock"},
		},
	}])
	some m in msgs
	contains(m, "/var/run/docker.sock")
}

# --- service account tokens -------------------------------------------------

test_automounted_token_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "replace",
		"path": "/spec/template/spec/automountServiceAccountToken",
		"value": true,
	}])
	some m in msgs
	contains(m, "automountServiceAccountToken")
}

test_omitted_automount_field_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "remove",
		"path": "/spec/template/spec/automountServiceAccountToken",
	}])
	some m in msgs
	contains(m, "automountServiceAccountToken")
}

# --- initContainers are held to the same standard ---------------------------

test_privileged_init_container_is_denied if {
	msgs := deny with input as json.patch(compliant_deployment, [{
		"op": "add",
		"path": "/spec/template/spec/initContainers",
		"value": [{
			"name": "seed",
			"image": "ghcr.io/acaacx/devsec-pipeline:de6ef896b2dced7e641783223a9b42a9f7b3945c",
			"securityContext": {
				"privileged": true,
				"runAsNonRoot": true,
				"allowPrivilegeEscalation": false,
				"readOnlyRootFilesystem": true,
				"capabilities": {"drop": ["ALL"]},
			},
			"resources": {"limits": {
				"cpu": "100m",
				"memory": "64Mi",
			}},
		}],
	}])
	some m in msgs
	contains(m, "is privileged")
}

# --- other workload kinds are not a way out --------------------------------

# Converting a Deployment to a StatefulSet must not opt out of the policy.
test_statefulset_is_also_checked if {
	msgs := deny with input as json.patch(compliant_deployment, [
		{
			"op": "replace",
			"path": "/kind",
			"value": "StatefulSet",
		},
		{
			"op": "replace",
			"path": "/spec/template/spec/containers/0/image",
			"value": "nginx:latest",
		},
	])
	some m in msgs
	contains(m, "':latest'")
}

test_bare_pod_is_also_checked if {
	msgs := deny with input as {
		"kind": "Pod",
		"metadata": {"name": "debug"},
		"spec": {"containers": [{
			"name": "debug",
			"image": "busybox:latest",
		}]},
	}
	some m in msgs
	contains(m, "':latest'")
}

# --- services ---------------------------------------------------------------

test_nodeport_service_is_denied if {
	msgs := deny with input as {
		"kind": "Service",
		"metadata": {"name": "pygoat"},
		"spec": {"type": "NodePort"},
	}
	some m in msgs
	contains(m, "NodePort")
}

test_loadbalancer_service_is_denied if {
	msgs := deny with input as {
		"kind": "Service",
		"metadata": {"name": "pygoat"},
		"spec": {"type": "LoadBalancer"},
	}
	some m in msgs
	contains(m, "LoadBalancer")
}

test_clusterip_service_is_allowed if {
	count(deny) == 0 with input as {
		"kind": "Service",
		"metadata": {"name": "pygoat"},
		"spec": {"type": "ClusterIP"},
	}
}
