from pathlib import Path
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_FILE = BASE_DIR / "severity_model.pkl"
FEATURES_FILE = BASE_DIR / "feature_columns.pkl"

model = joblib.load(MODEL_FILE)
model_features = joblib.load(FEATURES_FILE)


def prepare_input(scan_result):
    data = {feature: 0 for feature in model_features}

    data["response_code"] = scan_result["response_code"]
    data["response_size"] = scan_result["response_size"]
    data["error_message_present"] = scan_result["error_message_present"]
    data["data_exposure_detected"] = scan_result["data_exposure_detected"]
    data["auth_state"] = scan_result["auth_state"]

    attack_column = f"attack_type_{scan_result['attack_type']}"
    if attack_column in data:
        data[attack_column] = 1

    df = pd.DataFrame([data])
    return df


def predict_severity(scan_result):
    df = prepare_input(scan_result)
    prediction = model.predict(df)
    return prediction[0]