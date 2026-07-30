# Deployment-time policy for Kubernetes manifests, evaluated by Conftest.
#
# Checkov and Trivy already scan these manifests against their own rule sets, so
# this file is not here to duplicate them. It exists because the controls in
# deploy/k8s are load-bearing: the read-only root filesystem is why the app cannot
# write code into itself, the dropped capabilities are why an exploit stays
# unprivileged, and the resource limits are why one compromised pod is not a
# cluster-wide availability incident. A generic scanner reports those as advice.
# Here they are a build failure.
#
# Anything asserted below is satisfied by deploy/k8s today, so a violation means
# someone weakened the deployment - which is exactly the event worth blocking.
package main

import rego.v1

# ---------------------------------------------------------------------------
# Extracting the pod spec
#
# The wrapping differs per kind, so every rule below works against `podspec`
# rather than reaching into `input` directly - otherwise converting a Deployment
# to a StatefulSet would silently opt out of the entire policy. The definitions
# are mutually exclusive by kind, so they cannot conflict.
# ---------------------------------------------------------------------------
podspec := input.spec.template.spec if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
}

podspec := input.spec if input.kind == "Pod"

podspec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

# initContainers are held to the same standard as app containers. They routinely
# run as root "just to fix permissions", which hands an attacker a root-capable
# process in the same pod - so they are folded into one set rather than checked
# separately or, more usually, not at all.
all_containers contains c if some c in podspec.containers

all_containers contains c if some c in podspec.initContainers

resource_id := sprintf("%s/%s", [input.kind, object.get(input, ["metadata", "name"], "<unnamed>")])

# ---------------------------------------------------------------------------
# Image tags
# ---------------------------------------------------------------------------

# Tag of an image reference, or undefined when the reference is by digest or
# carries no tag. Splitting on the last path segment matters: a registry with a
# port (`registry.internal:5000/app`) puts a colon in an earlier segment, and a
# naive split would read "5000/app" as the tag.
image_tag(image) := tag if {
	not contains(image, "@")
	segments := split(image, "/")
	last := segments[count(segments) - 1]
	contains(last, ":")
	tag := split(last, ":")[1]
}

image_is_digest_pinned(image) if contains(image, "@sha256:")

image_has_tag(image) if image_tag(image)

deny contains msg if {
	some c in all_containers
	image_tag(c.image) == "latest"
	msg := sprintf(
		"%s: container %q uses the mutable tag ':latest'. A moving tag makes the running code unidentifiable after the fact and makes a rollback ambiguous; pin a digest or an immutable tag.",
		[resource_id, c.name],
	)
}

deny contains msg if {
	some c in all_containers
	not image_has_tag(c.image)
	not image_is_digest_pinned(c.image)
	msg := sprintf(
		"%s: container %q image %q has no tag, which resolves to ':latest'.",
		[resource_id, c.name, c.image],
	)
}

# ---------------------------------------------------------------------------
# Privilege
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	c.securityContext.privileged == true
	msg := sprintf(
		"%s: container %q is privileged. This disables essentially every container boundary and is never appropriate for an application workload.",
		[resource_id, c.name],
	)
}

deny contains msg if {
	some c in all_containers

	# object.get with a default of `true` is deliberate. A bare
	# `c.securityContext.allowPrivilegeEscalation != false` is *undefined* when the
	# field is absent, so the rule would silently pass exactly the case that
	# matters most - the omitted field, whose Kubernetes default is true. The unit
	# tests caught this; the naive spelling looked correct.
	object.get(c, ["securityContext", "allowPrivilegeEscalation"], true) != false
	msg := sprintf(
		"%s: container %q must set securityContext.allowPrivilegeEscalation: false. It defaults to true, so omitting it leaves setuid binaries usable as an escalation path.",
		[resource_id, c.name],
	)
}

# ---------------------------------------------------------------------------
# Running as a non-root user
#
# runAsNonRoot can be set on the pod or on the container, and the container value
# wins. Both spellings are accepted, but one of them has to be present: relying on
# the image's USER directive is not enough, because a later image rebuild can
# change it without any manifest changing.
# ---------------------------------------------------------------------------

container_non_root(c) if c.securityContext.runAsNonRoot == true

container_non_root(c) if {
	not has_key(object.get(c, "securityContext", {}), "runAsNonRoot")
	podspec.securityContext.runAsNonRoot == true
}

deny contains msg if {
	some c in all_containers
	not container_non_root(c)
	msg := sprintf(
		"%s: container %q must run as non-root. Set securityContext.runAsNonRoot: true on the container or the pod; the image's USER directive alone is not enforced by the API server.",
		[resource_id, c.name],
	)
}

deny contains msg if {
	some c in all_containers
	c.securityContext.runAsUser == 0
	msg := sprintf("%s: container %q sets runAsUser: 0.", [resource_id, c.name])
}

deny contains msg if {
	podspec.securityContext.runAsUser == 0
	msg := sprintf("%s: pod sets runAsUser: 0.", [resource_id])
}

# ---------------------------------------------------------------------------
# Filesystem and capabilities
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers

	# Defaults to false when absent, for the same reason as
	# allowPrivilegeEscalation above: an omitted field must fail, not vanish.
	object.get(c, ["securityContext", "readOnlyRootFilesystem"], false) != true
	msg := sprintf(
		"%s: container %q must set securityContext.readOnlyRootFilesystem: true. Mount an emptyDir for the paths that genuinely need writing rather than making the whole image writable.",
		[resource_id, c.name],
	)
}

deny contains msg if {
	some c in all_containers
	drops := object.get(c, ["securityContext", "capabilities", "drop"], [])
	not "ALL" in drops
	msg := sprintf(
		"%s: container %q must drop all capabilities (securityContext.capabilities.drop: [\"ALL\"]), then add back only what it provably needs.",
		[resource_id, c.name],
	)
}

deny contains msg if {
	some c in all_containers
	some added in object.get(c, ["securityContext", "capabilities", "add"], [])
	msg := sprintf(
		"%s: container %q adds capability %q. Adding capabilities back needs a written justification, not a manifest edit.",
		[resource_id, c.name, added],
	)
}

# ---------------------------------------------------------------------------
# Resource limits
#
# Absent limits are why a single compromised or looping pod becomes everyone
# else's outage. Both cpu and memory are required: a memory limit alone still
# allows a pod to consume every core on the node.
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in all_containers
	some resource in ["cpu", "memory"]
	not has_key(object.get(c, ["resources", "limits"], {}), resource)
	msg := sprintf(
		"%s: container %q has no %s limit. Without one, a runaway or hostile workload can starve every other pod on the node.",
		[resource_id, c.name, resource],
	)
}

# ---------------------------------------------------------------------------
# Host namespaces and host paths
#
# Each of these punches straight through the pod boundary: host namespaces expose
# the node's network, processes or IPC, and a hostPath mount hands out part of the
# node's filesystem - /var/run/docker.sock being the classic one-step escape.
# ---------------------------------------------------------------------------

deny contains msg if {
	some ns in ["hostNetwork", "hostPID", "hostIPC"]
	podspec[ns] == true
	msg := sprintf("%s: sets %s: true, which removes the pod's isolation from the node.", [resource_id, ns])
}

deny contains msg if {
	some v in podspec.volumes
	has_key(v, "hostPath")
	msg := sprintf(
		"%s: volume %q is a hostPath mount of %q. This exposes the node's filesystem to the pod.",
		[resource_id, v.name, object.get(v, ["hostPath", "path"], "<unknown>")],
	)
}

# ---------------------------------------------------------------------------
# Service account tokens
#
# Specific to this repository, and the sharpest rule here. PyGoat ships working
# SSRF and file-read labs. A mounted service-account token turns any of them into
# a credential for the Kubernetes API, so the default of mounting one is not
# acceptable for this workload.
# ---------------------------------------------------------------------------

deny contains msg if {
	podspec # only evaluate for kinds that carry a pod spec

	# Defaults to true when absent, matching Kubernetes' own default.
	object.get(podspec, "automountServiceAccountToken", true) != false
	msg := sprintf(
		"%s: must set automountServiceAccountToken: false. It defaults to true, and this application has deliberate SSRF and file-read vulnerabilities that would then reach the Kubernetes API.",
		[resource_id],
	)
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

deny contains msg if {
	input.kind == "Service"
	input.spec.type in {"LoadBalancer", "NodePort"}
	msg := sprintf(
		"%s: Service type %q publishes a deliberately vulnerable application beyond the cluster. Use ClusterIP and reach it with `kubectl port-forward`.",
		[resource_id, input.spec.type],
	)
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# object.get with a default cannot distinguish "absent" from "present but set to a
# falsy value", so key presence is tested against the key set instead.
has_key(obj, k) if k in object.keys(obj)
