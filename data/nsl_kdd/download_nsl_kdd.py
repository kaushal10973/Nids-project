# data/download_nsl_kdd.py
import os, urllib.request, gzip, shutil

URLS = {
"KDDTrain+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
"KDDTest+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
}

os.makedirs("data/raw", exist_ok=True)
for name, url in URLS.items():
    out = os.path.join("data/raw", name)
    if not os.path.exists(out):
        print("Downloading", name)
        urllib.request.urlretrieve(url, out)
print("Done.")