"""Native inference for the named local text model, separate from the OCS adapter."""

import math
import re
from collections import Counter

# The native engine owns this small labelled corpus. Held-out questions belong
# to the qualification client. A class is chosen by multinomial log-likelihood.
TRAINING = {
    "blue": [
        "sky sapphire ocean denim water blueberries cobalt sea",
        "sapphire sky azure cobalt ocean navy sea blueberries",
    ],
    "green": [
        "fern emerald emeralds grass mint leaf garden foliage",
        "grass leaves mint shamrock emeralds fern meadow green",
    ],
}


def tokenize(text):
    return re.findall(r"[a-z]+", text.lower())


def likelihoods():
    counts = {label: Counter(tokenize(" ".join(texts))) for label, texts in TRAINING.items()}
    vocabulary = sorted(set().union(*(words.keys() for words in counts.values())))
    return {
        label: {
            word: math.log((words[word] + 1) / (sum(words.values()) + len(vocabulary)))
            for word in vocabulary
        }
        for label, words in counts.items()
    }


FAST_INDEX = likelihoods()


class Unsupported(ValueError):
    pass


def invoke(bound_account, selected_route, selected_model, text, sent, output_limit):
    if (selected_route, selected_model) != ("local-primary", "reference-colour"):
        raise Unsupported("no such native endpoint")
    if sent.get("reasoning") != "off" or not 1 <= output_limit <= 8:
        raise Unsupported("unsupported native reasoning or output bound")
    if sent.get("tier") == "standard":
        lookup = likelihoods()
        used_tier = "standard"
    elif sent.get("tier") == "fast":
        lookup = FAST_INDEX
        used_tier = "fast"
    else:
        raise Unsupported("unsupported native execution tier")
    words = tokenize(text)
    if len(words) > 250:
        raise Unsupported("native input bound")
    useful = [word for word in words if word in lookup["blue"]]
    if useful:
        scores = {label: sum(weights[word] for word in useful) for label, weights in lookup.items()}
        label = max(scores, key=scores.__getitem__)
    else:
        label = "unknown"
    return {
        "account": bound_account,
        "route": "local-primary",
        "model": "reference-colour",
        "used": {"reasoning": "off", "tier": used_tier},
        "text": label,
        "readTokens": len(words),
        "emittedTokens": 1,
    }
