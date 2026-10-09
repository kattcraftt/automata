import argparse
import joblib
import numpy as np
import scipy.stats
import os

def extract_features(data):
    if len(data) < 4096:
        data = data.ljust(4096, b'\x00')
    data = data[:4096]
    arr = np.frombuffer(data, dtype=np.uint8)
    
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    hist = hist / 4096.0
    
    entropy = scipy.stats.entropy(hist + 1e-9, base=2)
    expected = np.ones(256) * (4096 / 256.0)
    chi2, _ = scipy.stats.chisquare(hist * 4096, expected)
    
    mean = np.mean(arr)
    std = np.std(arr)
    skew = scipy.stats.skew(arr)
    kurt = scipy.stats.kurtosis(arr)
    
    features = list(hist) + [entropy, chi2, mean, std, skew, kurt]
    return features

def classify_block(clf, data: bytes):
    features = extract_features(data)
    label = clf.predict([features])[0]
    probabilities = clf.predict_proba([features])[0]
    confidence = max(probabilities)
    classes = clf.classes_
    
    return {
        'label': label,
        'confidence': confidence,
        'probabilities': dict(zip(classes, probabilities))
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str)
    parser.add_argument('--block-size', type=int, default=4096)
    args = parser.parse_args()

    model_path = os.path.join(os.path.dirname(__file__), 'models', 'data_classifier.pkl')
    clf = joblib.load(model_path)

    with open(args.file, 'rb') as f:
        offset = 0
        while True:
            chunk = f.read(args.block_size)
            if not chunk:
                break
            result = classify_block(clf, chunk)
            print(f"Offset 0x{offset:08x}: {result['label']} (confidence: {result['confidence']:.2f})")
            offset += len(chunk)

if __name__ == '__main__':
    main()
