"""Set metrics with explicit empty denominators and separate retrieval outcomes."""


def divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def measure(rows, k=3):
    if not 1 <= k <= 100:
        raise ValueError("k must be between 1 and 100")
    tp = fp = fn = exact = abstained = unsupported = predicted_count = references = 0
    p_at_k = r_at_k = runtime = 0.0
    label_counts = {}
    retrieval_tp = retrieval_count = retrieval_reference = retrieval_k_tp = 0
    ambiguous_count = ambiguous_correct = 0
    for row in rows:
        predicted = set(row["predicted"])
        # Acceptable alternatives are annotated in advance. Choose the nearest acceptable set
        # using symmetric difference, then lexical order for deterministic ties.
        alternatives = row.get("acceptable_sets") or [row["expected"]]
        expected = min(
            (set(a) for a in alternatives), key=lambda a: (len(a ^ predicted), sorted(a))
        )
        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        exact += predicted == expected
        abstained += not predicted
        unsupported += row["unsupported_count"]
        predicted_count += len(predicted)
        references += row["complete_reference_count"]
        top = set(row["predicted"][:k])
        # Precision@k uses k slots, penalizing short/empty candidate lists.
        p_at_k += len(top & expected) / k
        r_at_k += divide(len(top & expected), len(expected))
        runtime += row["runtime_seconds"]
        retrieved = set(row["retrieved"])
        retrieval_tp += len(retrieved & expected)
        retrieval_count += len(retrieved)
        retrieval_reference += len(expected)
        retrieval_k_tp += len(set(row["retrieved"][:k]) & expected)
        for label in expected | predicted:
            counts = label_counts.setdefault(label, [0, 0, 0])
            counts[0] += label in expected and label in predicted
            counts[1] += label not in expected and label in predicted
            counts[2] += label in expected and label not in predicted
        if row.get("ambiguous"):
            ambiguous_count += 1
            ambiguous_correct += predicted == expected
    precision, recall = divide(tp, tp + fp), divide(tp, tp + fn)
    n = len(rows)
    macro = [divide(2 * a, 2 * a + b + c) for a, b, c in label_counts.values()]
    return {
        "case_count": n,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "candidate_precision": divide(retrieval_tp, retrieval_count),
        "candidate_recall": divide(retrieval_tp, retrieval_reference),
        "candidate_recall_at_k": divide(retrieval_k_tp, retrieval_reference),
        "retrieved_label_count": retrieval_count,
        "reference_label_count": retrieval_reference,
        "predicted_label_count": predicted_count,
        "set_precision": precision,
        "set_recall": recall,
        "micro_f1": divide(2 * tp, 2 * tp + fp + fn),
        "macro_label_f1": divide(sum(macro), len(macro)),
        "exact_match_accuracy": divide(exact, n),
        "precision_at_k": divide(p_at_k, n),
        "recall_at_k": divide(r_at_k, n),
        "k": k,
        "unsupported_mapping_rate": divide(unsupported, predicted_count),
        "abstention_rate": divide(abstained, n),
        "evidence_reference_completeness": divide(references, predicted_count),
        "runtime_seconds_per_observation": divide(
            runtime, sum(r["observation_count"] for r in rows)
        ),
        "ambiguous_case_count": ambiguous_count,
        "ambiguous_exact_match_accuracy": divide(ambiguous_correct, ambiguous_count),
        "empty_denominator_policy": "zero; inspect counts, zero is not evidence of quality",
    }
