package pipeline

# Deny pipelines when the rolling deployment timeout is too short
# NOTE Try removing the timeout on the "K8sRollingDeploy" to see the policy fail
deny[msg] {
	# Find all K8sRollingDeploy steps ...
	step = input.pipeline.stages[_].stage.spec.execution.steps[_].step
	step.type == "K8sRollingDeploy"

	# ... that have a timeout of less than "10m"
	time.parse_duration_ns(step.timeout) < time.parse_duration_ns("10m")

	# Show a human-friendly error message
	msg := sprintf(`step '%s' has a timeout that is under "10m"`, [step.identifier])
}

# Deny pipelines when the rolling deployment timeout is missing
# NOTE Try removing the timeout on the "K8sRollingDeploy" to see the policy fail
deny[msg] {
	# Find all K8sRollingDeploy steps ...
	step = input.pipeline.stages[_].stage.spec.execution.steps[_].step
	step.type == "K8sRollingDeploy"

	# ... that have no timeout specified
	not step.timeout

	# Show a human-friendly error message
	msg := sprintf("step '%s' has no timeout", [step.identifier])
}
