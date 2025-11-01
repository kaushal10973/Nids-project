# data/train_supervised.py
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support


Xt_train, y_train = joblib.load('models/nsl_train_xy.pkl')
Xt_test, y_test = joblib.load('models/nsl_test_xy.pkl')


clf = RandomForestClassifier(n_estimators=200, max_depth=None, n_jobs=-1, random_state=42)
clf.fit(Xt_train, y_train)


pred = clf.predict(Xt_test)
acc = accuracy_score(y_test, pred)
prec, rec, f1, _ = precision_recall_fscore_support(y_test, pred, average='binary')
print(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
print(classification_report(y_test, pred))


joblib.dump(clf, 'models/rf_supervised.pkl')
print('Saved → models/rf_supervised.pkl')