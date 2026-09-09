"""
Quantum-Inspired Anomaly Detector
----------------------------------
Encodes each signature event's behavioural features into a small
simulated quantum circuit (angle embedding across 4 qubits), then uses
the resulting quantum kernel (state-overlap similarity) with a
classical SVM to classify signing behaviour as normal or anomalous.

This runs entirely on PennyLane's classical simulator (`default.qubit`)
- no real quantum hardware is required - but genuinely uses quantum
feature-space embedding rather than a purely classical kernel, which is
the "quantum-inspired" technique this project is named for.
"""
import numpy as np
import pennylane as qml
from sklearn.svm import SVC
from sklearn.preprocessing import MinMaxScaler
import pickle

N_QUBITS = 4
dev = qml.device("default.qubit", wires=N_QUBITS)


@qml.qnode(dev)
def _quantum_embed_circuit(x):
    """Angle-embed features, entangle, and return the full statevector."""
    qml.AngleEmbedding(x, wires=range(N_QUBITS), rotation="Y")
    for i in range(N_QUBITS - 1):
        qml.CNOT(wires=[i, i + 1])
    qml.AngleEmbedding(x, wires=range(N_QUBITS), rotation="Z")
    return qml.state()


def _pad_features(X):
    """Features come in 5-dim; pad/trim to N_QUBITS for the circuit."""
    X = np.asarray(X, dtype=float)
    if X.shape[1] < N_QUBITS:
        pad = np.zeros((X.shape[0], N_QUBITS - X.shape[1]))
        X = np.hstack([X, pad])
    elif X.shape[1] > N_QUBITS:
        X = X[:, :N_QUBITS]
    return X * np.pi  # scale into a sensible rotation-angle range


def _embed_all(X):
    """Run each row through the quantum circuit once to get its statevector.
    Kernel overlaps are then just linear algebra on the cached states,
    instead of re-running the circuit for every pair (O(n) not O(n^2)
    circuit evaluations)."""
    X = _pad_features(X)
    return np.array([_quantum_embed_circuit(x) for x in X])


def build_kernel_matrix(A, B, states_a=None, states_b=None):
    states_a = _embed_all(A) if states_a is None else states_a
    states_b = _embed_all(B) if states_b is None else states_b
    K = np.abs(states_a @ states_b.conj().T) ** 2
    return K


class QuantumInspiredDetector:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.svm = SVC(kernel="precomputed", probability=True)
        self.X_train_ = None
        self.fitted = False

    def fit(self, X, y):
        X = self.scaler.fit_transform(X)
        self.train_states_ = _embed_all(X)
        K_train = build_kernel_matrix(None, None, self.train_states_, self.train_states_)
        self.svm.fit(K_train, y)
        self.X_train_ = X
        self.fitted = True
        return self

    def predict(self, X):
        if not self.fitted:
            raise RuntimeError("Detector not trained yet.")
        X = self.scaler.transform(X)
        test_states = _embed_all(X)
        K_test = build_kernel_matrix(None, None, test_states, self.train_states_)
        preds = self.svm.predict(K_test)
        probs = self.svm.predict_proba(K_test)[:, 1]
        return preds, probs

    def save(self, path="quantum_model.pkl"):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path="quantum_model.pkl"):
        with open(path, "rb") as f:
            return pickle.load(f)
