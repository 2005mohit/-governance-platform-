# Synthetic fixture: unsafe deserialization. The scanner should report
# UNSAFE_DESERIALIZE.
import pickle


def load_model(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)
