package main

# Deny messages are collected by conftest from the "deny" rule (a set of strings).

# --- Pod hardening ------------------------------------------------------------

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  not c.securityContext.runAsNonRoot
  msg := sprintf("%s/%s: container %q must set securityContext.runAsNonRoot=true", [input.metadata.namespace, input.metadata.name, c.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  c.securityContext.privileged == true
  msg := sprintf("%s/%s: container %q must not run privileged", [input.metadata.namespace, input.metadata.name, c.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  c.securityContext.allowPrivilegeEscalation == true
  msg := sprintf("%s/%s: container %q must not allow privilege escalation", [input.metadata.namespace, input.metadata.name, c.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  not c.resources
  msg := sprintf("%s/%s: container %q must define resource requests/limits", [input.metadata.namespace, input.metadata.name, c.name])
}

deny contains msg if {
  input.kind == "Pod"
  some i
  c := input.spec.containers[i]
  not c.resources.limits
  msg := sprintf("%s/%s: container %q must define resource limits", [input.metadata.namespace, input.metadata.name, c.name])
}

# --- Namespace PSA (Pod Security Admission) enforcement ----------------------

deny contains msg if {
  input.kind == "Namespace"
  not has_label(input, "pod-security.kubernetes.io/enforce")
  msg := sprintf("namespace %q must set PSA enforce=restricted", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Namespace"
  val := get_label(input, "pod-security.kubernetes.io/enforce")
  val != "restricted"
  msg := sprintf("namespace %q PSA enforce must be 'restricted' (found %q)", [input.metadata.name, val])
}

# --- Helpers -----------------------------------------------------------------

has_label(obj, key) if {
  obj.metadata.labels[key]
}

get_label(obj, key) := v if {
  v := obj.metadata.labels[key]
}
