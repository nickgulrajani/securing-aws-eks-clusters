package main

# Require restricted-level container security
deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("%s/%s: container %q must set securityContext.runAsNonRoot=true", [input.metadata.namespace, input.metadata.name, c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("%s/%s: container %q must not run privileged", [input.metadata.namespace, input.metadata.name, c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  c.securityContext.allowPrivilegeEscalation == true
  msg := sprintf("%s/%s: container %q must not allow privilege escalation", [input.metadata.namespace, input.metadata.name, c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.resources.limits
  msg := sprintf("%s/%s: container %q must define resource limits", [input.metadata.namespace, input.metadata.name, c.name])
}

# Namespace must enforce Pod Security Admission "restricted"
deny[msg] {
  input.kind == "Namespace"
  not input.metadata.labels["pod-security.kubernetes.io/enforce"]
  msg := sprintf("namespace %q must set PSA enforce=restricted", [input.metadata.name])
}

deny[msg] {
  input.kind == "Namespace"
  val := input.metadata.labels["pod-security.kubernetes.io/enforce"]
  val != "restricted"
  msg := sprintf("namespace %q PSA enforce must be 'restricted' (found %q)", [input.metadata.name, val])
}

