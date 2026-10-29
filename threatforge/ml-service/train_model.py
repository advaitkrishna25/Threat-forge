"""
ThreatForge Model Trainer
Trains an EMBER-compatible Random Forest classifier on static PE features.

Usage:
  python train_model.py --compact    # Trains lightweight ~3 MB model (model.pkl)
  python train_model.py --full       # Trains full high-capacity model (malware_model.pkl)
"""

import os
import sys
import argparse
import logging
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("trainer")

FEATURE_NAMES = [
    "size", "vsize", "imports", "exports", "has_debug", "has_relocations",
    "has_resources", "has_signature", "numstrings", "avlength", "paths", "urls",
    "number_of_sections", "section_entropy_mean", "section_entropy_max",
    "section_raw_size_mean", "section_raw_size_max", "section_virtual_size_mean",
    "section_virtual_size_max", "coff_timestamp", "coff_characteristics_count",
    "sizeof_code", "sizeof_headers", "dll_characteristics_count"
]


def find_dataset():
    candidates = [
        "features_25.csv",
        "../features_25.csv",
        "../../features_25.csv",
        "training_data.csv",
        "../training_data.csv",
        "../../training_data.csv",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None


def main():
    parser = argparse.ArgumentParser(description="Train ThreatForge Random Forest PE Malware Classifier")
    parser.add_argument("--compact", action="store_true", default=True, help="Train compact, GitHub-friendly model (default: True)")
    parser.add_argument("--full", action="store_true", help="Train full 300-estimator model")
    parser.add_argument("--dataset", type=str, default=None, help="Path to features CSV dataset")
    parser.add_argument("--output", type=str, default=None, help="Output .pkl path")
    parser.add_argument("--samples", type=int, default=None, help="Number of samples to read from dataset")
    args = parser.parse_args()

    dataset_path = args.dataset or find_dataset()
    if not dataset_path:
        logger.error("Dataset not found! Ensure features_25.csv or training_data.csv exists.")
        sys.exit(1)

    logger.info(f"Loading dataset from: {dataset_path}...")
    nrows = args.samples or (None if args.full else 100000)
    df = pd.read_csv(dataset_path, nrows=nrows)

    # Filter binary classification labels (0: clean, 1: malware)
    df = df[df["label"].isin([0, 1])]
    logger.info(f"Loaded {len(df)} samples. Class balance: {df['label'].value_counts().to_dict()}")

    X = df[FEATURE_NAMES]
    y = df["label"]

    split_idx = int(len(df) * 0.8)
    X_train, y_train = X.iloc[:split_idx], y.iloc[:split_idx]
    X_val, y_val = X.iloc[split_idx:], y.iloc[split_idx:]

    if args.full:
        logger.info("Training FULL Random Forest (300 estimators, unlimited depth)...")
        rf = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42, n_jobs=-1)
        default_out = "malware_model.pkl"
    else:
        logger.info("Training COMPACT Random Forest (50 estimators, max_depth=16)...")
        rf = RandomForestClassifier(n_estimators=50, max_depth=16, random_state=42, n_jobs=-1)
        default_out = "model.pkl"

    rf.fit(X_train, y_train)

    if len(X_val) > 0:
        val_preds = rf.predict(X_val)
        acc = accuracy_score(y_val, val_preds)
        logger.info(f"Validation Accuracy: {acc * 100:.2f}%")
        logger.info("\n" + classification_report(y_val, val_preds, target_names=["Clean (0)", "Malware (1)"]))

    out_file = args.output or default_out
    bundle = {
        "model": rf,
        "features": FEATURE_NAMES
    }

    logger.info(f"Saving model bundle to: {out_file} (compressed)...")
    joblib.dump(bundle, out_file, compress=3)
    size_mb = os.path.getsize(out_file) / (1024 * 1024)
    logger.info(f"Model saved successfully! File size: {size_mb:.2f} MB")


if __name__ == "__main__":
    main()

