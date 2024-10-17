package pipeline_approval\n\n# Deny pipelines that don't have an approval step\ndeny[sprintf(\"deployment stage '%s' does not have a HarnessApproval step\", [input.pipeline.stages[i].stage.name])] {\n    input.pipeline.stages[i].stage.type == \"Deployment\"  # Find all stages that are Deployments ...\n    not stages_with_approval[i]                          # ... that are not in the set of stages with HarnessApproval steps\n}\n\n# Find the set of stages that contain a HarnessApproval step - try removing the HarnessApproval step from your input to see the policy fail\nstages_with_approval[i] {\n    input.pipeline.stages[i].stage.spec.execution.steps[_].step.type == \"HarnessApproval\"\n}