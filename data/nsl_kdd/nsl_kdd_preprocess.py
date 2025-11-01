# data/nsl_kdd_preprocess.py
# data/nsl_kdd_preprocess.py
import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
import joblib, os


# NSL-KDD has 41 features + label + difficulty
COLS = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
'srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty']


TRAIN = 'data/raw/KDDTrain+.txt'
TEST = 'data/raw/KDDTest+.txt'


for p in [TRAIN, TEST]:
    assert os.path.exists(p), f"Missing: {p}. Run download script first."


# Load
train = pd.read_csv(TRAIN, names=COLS)
test = pd.read_csv(TEST, names=COLS)


# Binary label: normal -> 0, attack -> 1
train['target'] = (train['label'] != 'normal').astype(int)
test['target'] = (test['label'] != 'normal').astype(int)


X_train = train.drop(columns=['label','difficulty','target'])
y_train = train['target']
X_test = test.drop(columns=['label','difficulty','target'])
y_test = test['target']


cat = ['protocol_type','service','flag']
num = [c for c in X_train.columns if c not in cat]


pre = ColumnTransformer([
('cat', OneHotEncoder(handle_unknown='ignore'), cat),
('num', Pipeline([
('imp', SimpleImputer(strategy='median')),
('sc', StandardScaler())
]), num)
])


joblib.dump({'cat':cat,'num':num}, 'models/nsl_schema.pkl')
print('Saved schema → models/nsl_schema.pkl')


# Save preprocessor for reuse
pipe = Pipeline([('pre', pre)])
pipe.fit(X_train)
joblib.dump(pipe, 'models/nsl_preprocessor.pkl')
print('Saved preprocessor → models/nsl_preprocessor.pkl')


# Export transformed arrays for quick training
Xt_train = pipe.transform(X_train)
Xt_test = pipe.transform(X_test)
joblib.dump((Xt_train, y_train.to_numpy()), 'models/nsl_train_xy.pkl')
joblib.dump((Xt_test, y_test.to_numpy()), 'models/nsl_test_xy.pkl')
print('Saved transformed datasets.')