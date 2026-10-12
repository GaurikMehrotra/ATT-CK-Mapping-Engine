"""Transparent heuristic score; never a calibrated probability."""

from src.schemas.mappings import MappingStatus


def score(matches, assessment, config):
    deterministic = [m for m in matches if m.method == "deterministic_rule"]
    best = max(deterministic or matches, key=lambda m: (not m.missing, m.strength))
    factors = {
        "behavioral_strength": best.strength * config.strength_weight,
        "observation_directness": assessment["directness"] * config.directness_weight,
        "context_completeness": (0 if assessment["critical_missing"] else 1)
        * config.completeness_weight,
        "source_reliability": assessment["reliability"] * config.reliability_weight,
        "independent_source_agreement": min(max(assessment["independent_count"] - 1, 0), 1)
        * config.independence_weight,
        "contradiction_penalty": -config.contradiction_penalty
        if assessment["contradictions"]
        else 0,
    }
    raw = round(max(0, min(1, sum(factors.values()))), 6)
    if assessment["contradictions"]:
        status = MappingStatus.REJECTED
    elif not assessment["behavioral"]:
        status = MappingStatus.INSUFFICIENT
    elif assessment["critical_missing"]:
        status = MappingStatus.WEAK if raw >= config.weak_threshold else MappingStatus.INSUFFICIENT
    elif raw >= config.supported_threshold:
        status = MappingStatus.SUPPORTED
    elif raw >= config.weak_threshold:
        status = MappingStatus.WEAK
    else:
        status = MappingStatus.INSUFFICIENT
    explanation = "Weighted factors summed and clamped to [0,1]; not calibrated probability."
    if assessment["critical_missing"]:
        explanation += " Missing defining context prevents supported status regardless of score."
    return raw, factors, status, explanation
