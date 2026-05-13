from __future__ import annotations

from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / 'scanner_training_data.csv'
MODEL_FILE = BASE_DIR / 'severity_model.pkl'
FEATURES_FILE = BASE_DIR / 'model_features.pkl'
METRICS_FILE = BASE_DIR / 'training_metrics.json'

REQUIRED_COLUMNS = [
    'response_code',
    'response_size',
    'error_message_present',
    'data_exposure_detected',
    'auth_state',
    'attack_type',
    'severity_label',
]


def load_data() -> pd.DataFrame:
    if not DATA_FILE.exists():
        raise FileNotFoundError(f'Training data not found: {DATA_FILE}')

    df = pd.read_csv(DATA_FILE)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f'Missing required columns: {missing}')

    df = df[REQUIRED_COLUMNS].dropna().copy()
    for col in [
        'response_code',
        'response_size',
        'error_message_present',
        'data_exposure_detected',
        'auth_state',
        ]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.dropna().copy()
    df['response_code'] = df['response_code'].astype(int)
    df['response_size'] = df['response_size'].astype(int)
    df['error_message_present'] = df['error_message_present'].astype(int)
    df['data_exposure_detected'] = df['data_exposure_detected'].astype(int)
    df['auth_state'] = df['auth_state'].astype(int)
    df['attack_type'] = df['attack_type'].astype(str).str.strip()
    df['severity_label'] = df['severity_label'].astype(str).str.strip()
    return df


def build_features(df: pd.DataFrame):
    encoded = pd.get_dummies(df, columns=['attack_type'])
    X = encoded.drop(columns=['severity_label'])
    y = encoded['severity_label']
    return X, y


def evaluate_model(name: str, model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    report = classification_report(y_test, predictions, zero_division=0, output_dict=True)
    print(f'\n{name} Accuracy: {accuracy:.4f}')
    print(classification_report(y_test, predictions, zero_division=0))
    return {
        'name': name,
        'model': model,
        'accuracy': accuracy,
        'report': report,
    }


def choose_best(results: list[dict]) -> dict:
    # Prefer higher weighted f1-score, then accuracy.
    return max(
        results,
        key=lambda r: (r['report']['weighted avg']['f1-score'], r['accuracy'])
    )


def main() -> None:
    print('Loading training data...')
    df = load_data()
    print(f'Rows loaded: {len(df)}')
    print('\nSeverity distribution:')
    print(df['severity_label'].value_counts())

    X, y = build_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    dt_model = DecisionTreeClassifier(max_depth=4, random_state=42)
    rf_model = RandomForestClassifier(
        n_estimators=400,
        max_depth=7,
        min_samples_split=6,
        min_samples_leaf=3,
        max_features='sqrt',
        class_weight='balanced',
        random_state=42,
        )

    results = [
        evaluate_model('Decision Tree', dt_model, X_train, X_test, y_train, y_test),
        evaluate_model('Random Forest', rf_model, X_train, X_test, y_train, y_test),
    ]

    best = choose_best(results)
    print(f"\nSelected model: {best['name']}")

    joblib.dump(best['model'], MODEL_FILE)
    joblib.dump(list(X.columns), FEATURES_FILE)

    class_distribution = df['severity_label'].value_counts().to_dict()

    metrics = {
        'selected_model': best['name'],
        'decision_tree_accuracy': results[0]['accuracy'],
        'decision_tree_weighted_precision': results[0]['report']['weighted avg']['precision'],
        'decision_tree_weighted_recall': results[0]['report']['weighted avg']['recall'],
        'decision_tree_weighted_f1': results[0]['report']['weighted avg']['f1-score'],

        'random_forest_accuracy': results[1]['accuracy'],
        'random_forest_weighted_precision': results[1]['report']['weighted avg']['precision'],
        'random_forest_weighted_recall': results[1]['report']['weighted avg']['recall'],
        'random_forest_weighted_f1': results[1]['report']['weighted avg']['f1-score'],

        'class_distribution': class_distribution,
        'feature_count': len(X.columns),
        'rows_used': len(df),
    }

    METRICS_FILE.write_text(json.dumps(metrics, indent=2))

    print(f'Model saved to: {MODEL_FILE}')
    print(f'Features saved to: {FEATURES_FILE}')
    print(f'Metrics saved to: {METRICS_FILE}')


if __name__ == '__main__':
    main()