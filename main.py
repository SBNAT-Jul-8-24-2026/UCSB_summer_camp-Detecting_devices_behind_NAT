from __future__ import annotations

import csv
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from dts import FEATURE_KEYS, prepare_dataset

base_dir = Path(__file__).resolve().parent
model_path = base_dir / "decision_tree_model.joblib"
cm_path = base_dir / "confusion_matrix.png"
pair_csv_path = base_dir / "pair_features.csv"


def save_confusion_matrix(y_true, y_pred, output_path: Path) -> None:
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["different IP", "same IP"],
    ).plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"Confusion matrix saved to {output_path}")


def load_pair_csv(csv_path: Path) -> tuple[list[list[float]], list[int]]:
    X: list[list[float]] = []
    y: list[int] = []
    with csv_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        fields = reader.fieldnames or []
        missing = [key for key in FEATURE_KEYS if key not in fields]
        if missing:
            raise ValueError(f"CSV missing feature columns: {missing}")
        if "label" not in fields:
            raise ValueError("CSV missing label column")

        for row in reader:
            X.append([float(row[key]) for key in FEATURE_KEYS])
            y.append(int(float(row["label"])))
    return X, y


def get_dataset(random_state: int = 42) -> tuple[list[list[float]], list[int]]:
    # 1) Prefer existing pair_features.csv
    if pair_csv_path.is_file() and pair_csv_path.stat().st_size > 0:
        print(f"Found {pair_csv_path.name}, loading it...")
        return load_pair_csv(pair_csv_path)

    # 2) Otherwise build with prepare_dataset
    print(f"{pair_csv_path.name} not found, running prepare_dataset...")
    _, _, X, y = prepare_dataset(
        min_flows=3,
        max_flows=8,
        neg_per_flow=2,
        output_csv=pair_csv_path,
        random_state=random_state,
    )
    return X, y


def main(random_state: int = 42) -> None:
    X, y = get_dataset(random_state=random_state)
    if not X:
        raise SystemExit("Empty dataset; check pair_features.csv / feature files")

    feature_names = list(FEATURE_KEYS)
    print(f"Samples: {len(X)}  feature_dim={len(feature_names)}")
    print(f"Label balance (same IP=1): {sum(y)}/{len(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=random_state,
        stratify=y,
    )

    print("Training DecisionTreeClassifier...")
    clf = DecisionTreeClassifier(random_state=random_state, max_depth=5)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    print(f"Train={len(X_train)}, test={len(X_test)}")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"F1       : {f1_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"ROC-AUC  : {roc_auc_score(y_test, y_prob):.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, y_pred))

    print("\nTop feature importances:")
    ranked = sorted(
        zip(feature_names, clf.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )
    for name, importance in ranked[:15]:
        print(f"  {name:28s} {importance:.4f}")

    print("\nLast 10 feature importances:")
    for name, importance in ranked[-10:]:
        print(f"  {name:28s} {importance:.4f}")

    joblib.dump(
        {"model": clf, "feature_names": feature_names},
        model_path,
    )
    print(f"\nModel saved to {model_path}")
    save_confusion_matrix(y_test, y_pred, cm_path)


if __name__ == "__main__":
    main()
