# <Detection name>

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `<Table>` (connector) |
| **ATT&CK** | Txxxx.xxx Technique name |
| **Severity** | Low / Medium / High (and what raises it) |
| **Runs** | <frequency> over <period> |

## Goal
A sentence or two on what attacker behaviour this catches and why it's worth catching.

## How it works
What the query does, step by step. Explain each threshold and why it's set where it is.

## Technical context
Anything about the data source or the technique that an analyst needs to understand the alert.

## Blind spots
What this rule won't catch, and what could cover that.

## False positives
Known harmless causes, and how to tell them apart quickly.

## Validation
How to trigger the rule safely in a lab, and what the alert should look like.

## Response
First steps for the analyst who gets the alert.
