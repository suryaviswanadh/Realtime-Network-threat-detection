# D:\cyber_security_tool\Realtime-Network-threat-detection\training\train_random_forest.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler # Keep scaler for consistency
from sklearn.preprocessing import LabelEncoder # To convert text labels to numbers
from sklearn.metrics import accuracy_score, classification_report
import joblib # For saving the model, scaler, features, classes
import time # To time the training process

print("Starting training script (Chunk Processing Mode)...")

# --- 1. Define File, Columns, and Chunk Size ---

# ===>>> MODIFICATION 1: Switched to Tuesday file to get attack data <<<===
# Make sure 'Tuesday-WorkingHours.pcap_ISCX.csv' is in your 'training' folder
DATASET_FILENAME = 'Tuesday-WorkingHours.pcap_ISCX.csv' 
# ===>>> END MODIFICATION <<<===

# ===>>> MODIFICATION 2: Limit chunks to process to save memory <<<===
MAX_CHUNKS_TO_PROCESS = 1 # Process only the first 100,000 rows.
                          # This will be small enough to fit in memory.
# ===>>> END MODIFICATION <<<===

# IMPORTANT: Ensure these match your CSV headers EXACTLY (including spaces)
feature_names_original = [
    ' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
    ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
    'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
    'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
    ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
    ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
    ' Fwd Header Length.1', # This was in your CSV list, keeping it.
    'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
    ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
]
# IMPORTANT: Verify the exact name of the label column in your CSV!
LABEL_COLUMN_ORIGINAL = ' Label' # Example, check your file!

CHUNKSIZE = 100000 # Read 100,000 rows at a time

print(f"Processing dataset: {DATASET_FILENAME} in chunks of {CHUNKSIZE} rows.")
print(f"Will process a maximum of {MAX_CHUNKS_TO_PROCESS} chunk(s).")
print(f"Using {len(feature_names_original)} features and label '{LABEL_COLUMN_ORIGINAL}'.")

# --- 2. Process Data in Chunks ---
all_features_list = []
all_labels_list = []
chunk_count = 0
total_rows = 0

try:
    chunk_iterator = pd.read_csv(DATASET_FILENAME, chunksize=CHUNKSIZE, low_memory=False, iterator=True)

    for df_chunk in chunk_iterator:
        chunk_count += 1
        rows_in_chunk = len(df_chunk)
        total_rows += rows_in_chunk
        print(f"Processing chunk {chunk_count} ({rows_in_chunk} rows, total {total_rows})...")

        needed_cols_in_chunk = feature_names_original + [LABEL_COLUMN_ORIGINAL]
        missing_in_chunk = [col for col in needed_cols_in_chunk if col not in df_chunk.columns]
        if missing_in_chunk:
            print(f"ERROR: Chunk {chunk_count} is missing columns: {missing_in_chunk}")
            print("Please check the 'feature_names_original' list in the script.")
            exit()

        df_selected = df_chunk[needed_cols_in_chunk].copy()
        df_selected.columns = df_selected.columns.str.strip()
        feature_names = [name.strip() for name in feature_names_original]
        LABEL_COLUMN = LABEL_COLUMN_ORIGINAL.strip()

        for col in feature_names:
            df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce')

        df_selected.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_selected.fillna(0, inplace=True)

        X_chunk = df_selected[feature_names].values
        y_chunk_raw = df_selected[LABEL_COLUMN].values

        all_features_list.append(X_chunk)
        all_labels_list.append(y_chunk_raw)

        # --- MODIFICATION: Stop after processing the specified number of chunks ---
        if chunk_count >= MAX_CHUNKS_TO_PROCESS:
            print(f"Reached max chunks ({MAX_CHUNKS_TO_PROCESS}). Stopping file read.")
            break
        # --- END MODIFICATION ---

    print(f"\nFinished processing all {chunk_count} chunks ({total_rows} rows).")

except FileNotFoundError:
    print(f"ERROR: Dataset file not found at '{DATASET_FILENAME}'.")
    print("Please make sure the Tuesday CSV file is in the 'training' folder.")
    exit()
except Exception as e:
    print(f"ERROR: Could not process dataset chunk {chunk_count}.")
    print(f"Details: {e}")
    import traceback
    traceback.print_exc()
    exit()

# --- 3. Combine Processed Data ---
if not all_features_list:
    print("ERROR: No data was processed. Exiting.")
    exit()

print("Combining processed chunks...")
X_combined = np.vstack(all_features_list)
y_raw_combined = np.concatenate(all_labels_list)
print(f"Combined data shape: X={X_combined.shape}, y={y_raw_combined.shape}")

del all_features_list
del all_labels_list

# --- 4. Encode Labels and Scale Features ---
print("Encoding combined labels...")
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y_raw_combined)
print(f"Labels encoded. {len(label_encoder.classes_)} classes found: {list(label_encoder.classes_)}")

# --- CRITICAL CHECK ---
if len(label_encoder.classes_) <= 1:
    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("ERROR: Only one class (e.g., 'BENIGN') was found in the processed data.")
    print("This means the model cannot learn to detect attacks.")
    print(f"Please try a different CSV file (one that contains attacks) or increase MAX_CHUNKS_TO_PROCESS.")
    print("Aborting training.")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    exit()
# --- END CHECK ---

print("Scaling combined features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_combined)

# --- MODIFICATION: Remove sampling code, use the 1-chunk dataset directly ---
X_sample, y_sample = X_scaled, y
print(f"\nUsing data size: X={X_sample.shape}, y={y_sample.shape}")
del X_scaled
del y
# --- END MODIFICATION ---

# --- 5. Split Data ---
print("Splitting data into training (80%) and testing (20%) sets...")
try:
    X_train, X_test, y_train, y_test = train_test_split(X_sample, y_sample, test_size=0.2, random_state=42, stratify=y_sample)
    print(f"Training set shape: {X_train.shape}, Testing set shape: {X_test.shape}")
except ValueError as e:
     print(f"\nERROR during train/test split: {e}")
     print("This often happens if some classes have very few samples (e.g., only 1).")
     print("Consider increasing MAX_CHUNKS_TO_PROCESS to get more data.")
     print("\nLabel Distribution in this sample:")
     print(pd.Series(y_sample).value_counts()) # Show distribution
     exit()
del X_sample
del y_sample

# --- 6. Train Model ---
print("\nTraining Random Forest model (n_estimators=100)...")
print("(Using n_jobs=1 to conserve memory. This may take some time.)")
start_time = time.time()
# Use n_jobs=1 to force single-core training (uses less memory)
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=1, verbose=1)
try:
    model.fit(X_train, y_train)
except MemoryError as e:
    print(f"\nERROR: Ran out of memory during model fitting: {e}")
    print("Even with 1 chunk, the data is too large for available RAM.")
    print("Try reducing 'n_estimators' (e.g., to 50) or contact support.")
    exit()
except Exception as e:
     print(f"\nERROR during model fitting: {e}")
     exit()

end_time = time.time()
print(f"Model training finished in {end_time - start_time:.2f} seconds.")

# --- 7. Evaluate Model ---
print("\nEvaluating model performance on the test set...")
try:
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0)
    print(report)
except Exception as e:
    print(f"Could not generate full evaluation report: {e}")

# --- 8. Save Model, Scaler, Features, and Classes ---
OUTPUT_DIR = ".."
print(f"\nSaving model and supporting files to main project directory: {OUTPUT_DIR}/")
try:
    joblib.dump(model, f'{OUTPUT_DIR}/rf_model.joblib')
    joblib.dump(scaler, f'{OUTPUT_DIR}/rf_scaler.joblib')
    joblib.dump(feature_names, f'{OUTPUT_DIR}/rf_feature_names.joblib') # Save stripped names
    joblib.dump(label_encoder.classes_, f'{OUTPUT_DIR}/rf_classes.joblib')

    print("Files saved successfully:")
    print(f"- {OUTPUT_DIR}/rf_model.joblib")
    print(f"- {OUTPUT_DIR}/rf_scaler.joblib")
    print(f"- {OUTPUT_DIR}/rf_feature_names.joblib")
    print(f"- {OUTPUT_DIR}/rf_classes.joblib")
except Exception as e:
    print(f"\nERROR saving files: {e}")

print("\nTraining script finished.")