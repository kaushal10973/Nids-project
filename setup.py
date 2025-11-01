from setuptools import setup, find_packages

setup(
    name="nids",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'Flask>=3.0.0',
        'scapy>=2.5.0',
        'scikit-learn>=1.3.2',
        'pandas>=2.1.3',
        'numpy>=1.26.2',
        'joblib>=1.3.2',
        'PyYAML>=6.0.1',
    ],
    python_requires='>=3.10',
)