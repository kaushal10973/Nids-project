
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NSL-KDD column names
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

# Attack category mapping
ATTACK_CATEGORIES = {
    'normal': 'Normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'processtable': 'DoS',
    'udpstorm': 'DoS', 'apache2': 'DoS', 'worm': 'DoS',
    
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

def load_nsl_kdd_data(train_path, test_path=None):
    """Load and preprocess NSL-KDD dataset."""
    logger.info(f"Loading training data from {train_path}")
    
    # Load training data
    df_train = pd.read_csv(train_path, names=COLUMN_NAMES, header=None)
    
    # Load test data if provided
    df_test = None
    if test_path and os.path.exists(test_path):
        logger.info(f"Loading test data from {test_path}")
        df_test = pd.read_csv(test_path, names=COLUMN_NAMES, header=None)
    
    return df_train, df_test

def preprocess_data(df):
    """Preprocess NSL-KDD data."""
    logger.info("Preprocessing data...")
    
    # Remove difficulty column
    if 'difficulty' in df.columns:
        df = df.drop('difficulty', axis=1)
    
    # Map attack labels to categories
    df['label'] = df['label'].str.rstrip('.').str.lower()
    df['category'] = df['label'].map(lambda x: ATTACK_CATEGORIES.get(x, 'Unknown'))
    
    # Encode categorical features
    categorical_cols = ['protocol_type', 'service', 'flag']
    le_dict = {}
    
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        le_dict[col] = le
    
    # Encode target variable
    label_encoder = LabelEncoder()
    df['target'] = label_encoder.fit_transform(df['category'])
    
    # Separate features and target
    X = df.drop(['label', 'category', 'target'], axis=1)
    y = df['target']
    
    return X, y, label_encoder, le_dict

def train_random_forest(X_train, y_train, X_test=None, y_test=None):
    """Train Random Forest classifier."""
    logger.info("Training Random Forest model...")
    
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    rf_model.fit(X_train, y_train)
    
    # Evaluate
    train_accuracy = rf_model.score(X_train, y_train)
    logger.info(f"Training accuracy: {train_accuracy:.4f}")
    
    if X_test is not None and y_test is not None:
        test_accuracy = rf_model.score(X_test, y_test)
        logger.info(f"Test accuracy: {test_accuracy:.4f}")
        
        y_pred = rf_model.predict(X_test)
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred))
    
    return rf_model

def train_ensemble(X_train, y_train):
    """Train ensemble model."""
    logger.info("Training ensemble model...")
    
    # Create base classifiers
    rf = RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42)
    dt = DecisionTreeClassifier(max_depth=15, random_state=42)
    
    # Create voting classifier
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('dt', dt)],
        voting='soft'
    )
    
    ensemble.fit(X_train, y_train)
    
    train_accuracy = ensemble.score(X_train, y_train)
    logger.info(f"Ensemble training accuracy: {train_accuracy:.4f}")
    
    return ensemble

def create_dummy_models():
    """Create dummy models for testing when NSL-KDD is not available."""
    logger.warning("Creating dummy models for testing (not for production use)")
    
    # Generate synthetic data
    n_samples = 1000
    n_features = 41
    
    X_dummy = np.random.rand(n_samples, n_features)
    y_dummy = np.random.randint(0, 5, n_samples)
    
    # Train simple models
    rf_model = RandomForestClassifier(n_estimators=10, random_state=42)
    rf_model.fit(X_dummy, y_dummy)
    
    ensemble_model = VotingClassifier(
        estimators=[
            ('rf', RandomForestClassifier(n_estimators=5, random_state=42)),
            ('dt', DecisionTreeClassifier(max_depth=10, random_state=42))
        ],
        voting='soft'
    )
    ensemble_model.fit(X_dummy, y_dummy)
    
    return rf_model, ensemble_model

def main():
    """Main training function."""
    
    # Paths to NSL-KDD dataset
    train_path = 'data/nsl_kdd/KDDTrain+.txt'
    test_path = 'data/nsl_kdd/KDDTest+.txt'
    
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    # Check if NSL-KDD data exists
    if os.path.exists(train_path):
        # Load real data
        df_train, df_test = load_nsl_kdd_data(train_path, test_path)
        
        # Preprocess
        X_train, y_train, label_encoder, le_dict = preprocess_data(df_train)
        
        if df_test is not None:
            X_test, y_test, _, _ = preprocess_data(df_test)
        else:
            # Split training data
            X_train, X_test, y_train, y_test = train_test_split(
                X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
            )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Random Forest
        rf_model = train_random_forest(X_train_scaled, y_train, X_test_scaled, y_test)
        
        # Train Ensemble
        ensemble_model = train_ensemble(X_train_scaled, y_train)
        
        # Save label encoder and scaler
        joblib.dump(label_encoder, 'models/label_encoder.pkl')
        joblib.dump(scaler, 'models/scaler.pkl')
        joblib.dump(le_dict, 'models/feature_encoders.pkl')
        
    else:
        logger.warning(f"NSL-KDD data not found at {train_path}")
        logger.warning("Creating dummy models for testing only")
        rf_model, ensemble_model = create_dummy_models()
    
    # Save models
    joblib.dump(rf_model, 'models/model_rf.pkl')
    joblib.dump(ensemble_model, 'models/model_ensemble.pkl')
    
    logger.info("Models saved successfully!")
    logger.info("Random Forest: models/model_rf.pkl")
    logger.info("Ensemble: models/model_ensemble.pkl")

if __name__ == '__main__':
    main()

