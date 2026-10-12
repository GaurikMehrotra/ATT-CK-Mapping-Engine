"""Offline TF-IDF metadata retrieval creates unverified candidates only."""

import math
import re
from collections import Counter

from src.rules.behavior import RuleMatch

STOP = {
    "the",
    "and",
    "with",
    "from",
    "that",
    "this",
    "for",
    "are",
    "can",
    "may",
    "have",
    "technique",
    "adversaries",
    "using",
    "use",
    "into",
    "not",
    "will",
    "their",
    "such",
}


def terms(text):
    return [t for t in re.findall(r"[a-z][a-z0-9_-]{2,}", text.casefold()) if t not in STOP]


class MetadataRetriever:
    def __init__(self, catalog):
        self.vectors = {}
        docs = {}
        frequency = Counter()
        for tid, t in catalog["techniques"].items():
            if t["revoked"] or t["deprecated"]:
                continue
            text = " ".join([t["name"], t["description"], t["detection"], *t["data_sources"]])
            docs[tid] = Counter(terms(text))
            frequency.update(docs[tid].keys())
        self.idf = {
            term: math.log((1 + len(docs)) / (1 + count)) + 1 for term, count in frequency.items()
        }
        for tid, counts in docs.items():
            vector = {
                word: (1 + math.log(count)) * self.idf[word] for word, count in counts.items()
            }
            norm = math.sqrt(sum(v * v for v in vector.values()))
            self.vectors[tid] = {w: v / norm for w, v in vector.items()} if norm else {}

    def retrieve(self, observation, limit=3):
        counts = Counter(terms(observation.description))
        query = {w: (1 + math.log(c)) * self.idf[w] for w, c in counts.items() if w in self.idf}
        norm = math.sqrt(sum(v * v for v in query.values()))
        if not norm or not limit:
            return []
        scored = [
            (sum(v * vector.get(w, 0) for w, v in query.items()) / norm, tid)
            for tid, vector in self.vectors.items()
        ]
        return [
            RuleMatch(
                tid,
                [observation.observation_id],
                "metadata-tfidf@1.0",
                0.2,
                ["Defining behavioral evidence; metadata similarity is retrieval only"],
                f"Offline ATT&CK metadata cosine similarity {score:.3f}",
                ["Text similarity does not prove technique execution"],
                "metadata_retrieval",
            )
            for score, tid in sorted(scored, key=lambda x: (-x[0], x[1]))[:limit]
            if score >= 0.08
        ]
