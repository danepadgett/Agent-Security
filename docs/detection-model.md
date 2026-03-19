# Detection Model

The detection model converts raw telemetry into meaningful security findings.

## Inputs

The current system evaluates:
- file events
- new process events
- command features
- execution context

## Approach

The current model is deterministic and rule-based.

It looks for combinations of suspicious signals such as:
- unusual execution paths
- suspicious filenames or file locations
- risky command characteristics
- relationships between new files and new processes

## Output

The result of this stage is a detection record that can later be:
- logged
- grouped into an incident
- passed to the response layer

## Philosophy

The detection system is intentionally transparent and explainable. The goal is to build a trustworthy base before adding AI-assisted threat interpretation.