"""Dependency-free BM25 retrieval over the runbook corpus."""

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "a an and are as at be by for from has have in is it its of on or that the this to was were will with we our not no".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


@dataclass(frozen=True)
class RunbookDoc:
    id: int
    title: str
    category: str
    tags: str
    content: str
    recommended_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RetrievedRunbook:
    id: int
    title: str
    category: str
    score: float
    snippet: str
    recommended_actions: list[str]

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "category": self.category, "score": round(self.score, 3)}


class BM25Retriever:
    def __init__(self, docs: list[RunbookDoc], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        # title and tags are repeated so that matches there weigh more than body matches
        self._tokens = [tokenize(f"{d.title} {d.title} {d.tags} {d.tags} {d.content}") for d in docs]
        self._tf = [Counter(t) for t in self._tokens]
        self._avg_len = (sum(len(t) for t in self._tokens) / len(docs)) if docs else 0.0
        df: Counter[str] = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = len(docs)
        self._idf = {term: math.log(1 + (n - f + 0.5) / (f + 0.5)) for term, f in df.items()}

    def search(self, query: str, k: int = 3) -> list[RetrievedRunbook]:
        q_terms = tokenize(query)
        if not q_terms or not self.docs:
            return []
        scored: list[tuple[float, int]] = []
        for i, tf in enumerate(self._tf):
            length = len(self._tokens[i]) or 1
            score = 0.0
            for term in set(q_terms):
                f = tf.get(term)
                if not f:
                    continue
                denom = f + self.k1 * (1 - self.b + self.b * length / self._avg_len)
                score += self._idf[term] * f * (self.k1 + 1) / denom
            if score > 0:
                scored.append((score, i))
        scored.sort(key=lambda s: (-s[0], self.docs[s[1]].id))
        out = []
        for score, i in scored[: max(k, 0)]:
            d = self.docs[i]
            out.append(RetrievedRunbook(d.id, d.title, d.category, score, d.content[:300], list(d.recommended_actions)))
        return out
