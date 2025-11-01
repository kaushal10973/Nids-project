# data/train_unsupervised.py
# Anomaly model for *live* features (flow stats). It does not depend on NSL-KDD schema.
import numpy as np, joblib
from sklearn.ensemble import IsolationForest


# We will bootstrap the model with a short benign baseline you collect later.
# For now, start with a neutral model that we will partial-fit after startup.


# Feature order (must match backend.feature_extractor.LIVE_FEATURES):
# [pkts, bytes, duration, mean_pkt_size, pps, bps]


# Initialize with a tiny benign-like cloud to avoid degenerate trees
rng = np.random.RandomState(42)
seed = rng.normal(loc=[20, 15000, 3.0, 750, 8, 40000], scale=[5, 5000, 1.0, 200, 3, 15000], size=(512,6))


iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
iso.fit(seed)
joblib.dump(iso, 'models/iforest_live.pkl')
print('Saved → models/iforest_live.pkl')