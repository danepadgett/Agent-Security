# Response Model

The response model determines what action to take once suspicious behavior crosses configured thresholds.

## Supported Response Types

- process termination
- file quarantine
- simulated response only

## Policy Controls

The response layer is controlled by runtime policy, including:
- `simulation_mode`
- `enable_process_kill`
- `enable_file_quarantine`
- `kill_threshold`
- `quarantine_threshold`

## Guardrails

The system includes guardrails to reduce unsafe or overly destructive behavior. These guardrails are intended to make development safer and lower the risk of accidental damage.

## Development Approach

The response layer is being built incrementally:
1. observe behavior
2. log decisions
3. simulate responses
4. enable real responses behind policy flags