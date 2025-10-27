# monitoring/ml_engine.py
import joblib
import numpy as np
import math
from collections import defaultdict

class MLSecurityEngine:
    """
    Analyzes pre-calculated flow features using loaded, pre-trained models.
    """
    def __init__(self):
        self.predictions_made = 0
        self.rf_model = None
        self.rf_scaler = None
        self.rf_feature_names = None
        self.rf_classes = None
        self.is_rf_available = False
        
        try:
            # Load all necessary components saved during training
            self.rf_model = joblib.load('rf_model.joblib')
            self.rf_scaler = joblib.load('rf_scaler.joblib')
            self.rf_feature_names = joblib.load('rf_feature_names.joblib')
            self.rf_classes = joblib.load('rf_classes.joblib')
            self.is_rf_available = True
            print("[ML Engine] Loaded pre-trained Random Forest model and supporting files.")
            print(f"[ML Engine] Model expects {len(self.rf_feature_names)} features.")
            print(f"[ML Engine] Model can predict classes: {list(self.rf_classes)}")
        except FileNotFoundError:
            print("[ML Engine] ERROR: Pre-trained model files (rf_model.joblib, etc.) not found.")
            print("[ML Engine] Please run the training script first.")
            print("[ML Engine] ML predictions will be disabled.")
        except Exception as e:
            print(f"[ML Engine] ERROR loading Random Forest components: {e}")
            self.is_rf_available = False
            
    def _extract_features_from_flow(self, flow_features_dict, feature_keys):
        """
        Extracts features from a flow dictionary based on the required keys list,
        ensuring the correct order.
        """
        features = []
        if not feature_keys:
             print("[ML Engine] ERROR: Feature names list is empty.")
             return None
             
        for key in feature_keys:
            # The flow.py dictionary and training feature keys were
            # stripped of spaces, so they should match.
            val = flow_features_dict.get(key, 0.0) 
            
            if val is None or not isinstance(val, (int, float)):
                val = 0.0
            elif math.isnan(val) or math.isinf(val):
                val = 0.0
            
            features.append(val)
        
        if len(features) != len(feature_keys):
            print(f"[ML Engine] FATAL: Feature count mismatch! Expected {len(feature_keys)}, got {len(features)}.")
            return None # Indicate failure
            
        return features

    def analyze_flow(self, flow_features_dict):
        """
        Analyzes a single completed flow's features using the loaded RF model.
        """
        if not self.is_rf_available or not self.rf_model:
            return {'overall_threat_level': 0.0, 'threat_class': {'class': 'Benign', 'confidence': 1.0}}

        self.predictions_made += 1
        
        # Find the 'normal' class label
        normal_class = 'BENIGN'
        for cls_name in self.rf_classes:
            if str(cls_name).upper() == 'BENIGN':
                normal_class = cls_name
                break
        
        final_threat_level = 0.0
        final_class = normal_class
        final_confidence = 1.0
        
        try:
            # 1. Extract features in the EXACT order the model expects
            rf_features = self._extract_features_from_flow(flow_features_dict, self.rf_feature_names)
            
            if rf_features: # If extraction was successful
                # 2. Scale the features
                features_array_rf = np.array(rf_features).reshape(1, -1)
                features_scaled_rf = self.rf_scaler.transform(features_array_rf)
                
                # 3. Predict probabilities
                probabilities = self.rf_model.predict_proba(features_scaled_rf)[0]
                max_proba_index = np.argmax(probabilities)
                
                # 4. Get class name and confidence
                predicted_class = self.rf_classes[max_proba_index]
                confidence = probabilities[max_proba_index]
                
                # 5. Record detection if not 'BENIGN'
                if predicted_class.upper() != 'BENIGN' and confidence > 0.7:
                    final_class = predicted_class
                    final_confidence = confidence
                    final_threat_level = confidence
                else:
                    final_class = predicted_class # Show 'BENIGN'
                    final_confidence = confidence
                    final_threat_level = 0.0

        except Exception as e:
            print(f"[ML Engine] Error during RF prediction: {e}")
            import traceback
            traceback.print_exc()
            return {'overall_threat_level': 0.0, 'threat_class': {'class': 'Benign (Error)', 'confidence': 1.0}}

        return {
            'overall_threat_level': final_threat_level,
            'threat_class': {'class': final_class, 'confidence': final_confidence}
        }

    def get_ml_stats(self):
        """Returns stats including all models."""
        model_types = []
        if self.is_rf_available: model_types.append('Random Forest (Pre-trained)')
        
        return {
            'models_available': self.is_rf_available,
            'models_trained': self.is_rf_available,
            'rf_available': self.is_rf_available,
            'training_samples': "N/A (Pre-trained)",
            'predictions_made': self.predictions_made,
            'model_types': model_types
        }