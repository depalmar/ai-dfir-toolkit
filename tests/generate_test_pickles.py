#!/usr/bin/env python3
"""
Pickle test file generator for ai-dfir-detections.

Generates a "malicious" pickle that triggers YARA rules in
03-model-supply-chain/pickle_malicious_opcodes.yar but performs
only a harmless print() if loaded.

Run:
    python3 generate_test_pickles.py

Outputs:
    pickle_test_malicious.pkl
    pickle_test_benign.pkl
"""

import pickle
import builtins


class HarmlessPrint:
    """Reduce-based pickle that calls print() on load.

    The class is constructed during pickling but never instantiated
    directly. __reduce__ tells pickle: "to reconstruct me, call
    builtins.print with this argument tuple."
    """

    def __reduce__(self):
        message = (
            "YARA test - if you see this, do not run untrusted pickles. "
            "This is the ai-dfir-detections pickle malware test artifact."
        )
        return (builtins.print, (message,))


def main():
    # Malicious-pattern pickle (matches GLOBAL+REDUCE rules in YARA)
    with open("pickle_test_malicious.pkl", "wb") as f:
        pickle.dump(HarmlessPrint(), f, protocol=4)
    print("Wrote pickle_test_malicious.pkl")

    # Benign pickle: a plain dict, no GLOBAL+REDUCE chains for dangerous modules
    with open("pickle_test_benign.pkl", "wb") as f:
        pickle.dump(
            {
                "model_name": "benign-test-model",
                "weights_uri": "https://example.com/weights",
                "version": "1.0.0",
            },
            f,
            protocol=4,
        )
    print("Wrote pickle_test_benign.pkl")


if __name__ == "__main__":
    main()
