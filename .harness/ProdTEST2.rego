package pipeline

# Deny pipelines that do not use allowed environments 
# NOTE: Try removing "nonprod" from the 'allowed_environments' list to see the policy fail
deny[msg] {
	# Find all deployment stages
	stage = input.pipeline.stages[_].stage
	stage.type == "Deployment"

	environments := [s | s = stage.spec.environments.values[_].identifier]

	# For each environment ...
	environment := environments[_]

	# ... check if it's present in the allowed environments
	not contains(allowed_environments, environment)

	# Show a human-friendly error message
	msg := sprintf("deployment stage '%s' cannot be deployed to environment '%s'", [stage.name, environment])
}

# Environments that can be used for deployment
allowed_environments = {"stage", "nonprod"}

contains(arr, elem) {
	arr[_] = elem
}
