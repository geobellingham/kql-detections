# <Detection name>

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `<Table>` (connector) |
| **ATT&CK** | Txxxx.xxx Technique name |
| **Severity** | Low / Medium / High (and what raises it) |
| **Runs** | <frequency> over <period> |

## Goal
One or two sentences: what attacker behaviour this catches and why it matters.

## Strategy
How the query works, step by step. Explain each threshold and why it's set where it is.

## Technical context
What an analyst needs to know about the data source and the technique to understand the alert.

## Blind spots
What this rule will **not** catch, and what covers that gap.

## False positives
Known benign causes, and how to tell them apart quickly.

## Validation
How to trigger the rule safely in a lab, and what the resulting alert looks like.

## Response
First steps for the analyst who receives the alert.
