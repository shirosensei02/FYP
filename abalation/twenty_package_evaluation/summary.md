# Final classification by prompt version

### generic (n=40)

| Classification | Count | % |
|---|---|---|
| Supported fix | 19 | 47.5% |
| Needs verification | 1 | 2.5% |
| Security failure | 4 | 10.0% |
| Functional failure | 1 | 2.5% |
| Inconclusive | 15 | 37.5% |

### enriched (n=40)

| Classification | Count | % |
|---|---|---|
| Supported fix | 22 | 55.0% |
| Needs verification | 2 | 5.0% |
| Security failure | 3 | 7.5% |
| Functional failure | 1 | 2.5% |
| Inconclusive | 12 | 30.0% |

### CoT (n=40)

| Classification | Count | % |
|---|---|---|
| Supported fix | 21 | 52.5% |
| Needs verification | 0 | 0.0% |
| Security failure | 5 | 12.5% |
| Functional failure | 1 | 2.5% |
| Inconclusive | 13 | 32.5% |

## Per model

### generic / openai/gpt-5.3-codex (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 11 | 55.0% |
| Needs verification | 0 | 0.0% |
| Security failure | 3 | 15.0% |
| Functional failure | 0 | 0.0% |
| Inconclusive | 6 | 30.0% |

### generic / anthropic/claude-sonnet-5 (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 8 | 40.0% |
| Needs verification | 1 | 5.0% |
| Security failure | 1 | 5.0% |
| Functional failure | 1 | 5.0% |
| Inconclusive | 9 | 45.0% |

### enriched / openai/gpt-5.3-codex (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 10 | 50.0% |
| Needs verification | 0 | 0.0% |
| Security failure | 2 | 10.0% |
| Functional failure | 1 | 5.0% |
| Inconclusive | 7 | 35.0% |

### enriched / anthropic/claude-sonnet-5 (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 12 | 60.0% |
| Needs verification | 2 | 10.0% |
| Security failure | 1 | 5.0% |
| Functional failure | 0 | 0.0% |
| Inconclusive | 5 | 25.0% |

### CoT / openai/gpt-5.3-codex (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 10 | 50.0% |
| Needs verification | 0 | 0.0% |
| Security failure | 1 | 5.0% |
| Functional failure | 1 | 5.0% |
| Inconclusive | 8 | 40.0% |

### CoT / anthropic/claude-sonnet-5 (n=20)

| Classification | Count | % |
|---|---|---|
| Supported fix | 11 | 55.0% |
| Needs verification | 0 | 0.0% |
| Security failure | 4 | 20.0% |
| Functional failure | 0 | 0.0% |
| Inconclusive | 5 | 25.0% |

Runs with a pipeline exception (counted as Inconclusive): 0 of 120
