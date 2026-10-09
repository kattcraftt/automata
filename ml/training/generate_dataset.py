import os
import gzip
import lzma
import bz2
import argparse
import random
import csv
import string
import numpy as np
import scipy.stats

def generate_compressed():
    data = os.urandom(8192)
    choice = random.choice([gzip.compress, lzma.compress, bz2.compress])
    compressed = choice(data)
    return compressed[:4096].ljust(4096, b'\x00')

def generate_encrypted():
    return os.urandom(4096)

def generate_random():
    return os.urandom(4096)

def generate_plaintext():
    text = " ".join("".join(random.choices(string.ascii_letters, k=random.randint(3, 10))) for _ in range(1000))
    return text.encode('utf-8')[:4096].ljust(4096, b' ')

def extract_features(data):
    if len(data) < 4096:
        data = data.ljust(4096, b'\x00')
    data = data[:4096]
    arr = np.frombuffer(data, dtype=np.uint8)
    
    # Byte frequency histogram
    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    hist = hist / 4096.0
    
    # Entropy
    entropy = scipy.stats.entropy(hist + 1e-9, base=2)
    
    # Chi-squared
    expected = np.ones(256) * (4096 / 256.0)
    chi2, _ = scipy.stats.chisquare(hist * 4096, expected)
    
    # Stats
    mean = np.mean(arr)
    std = np.std(arr)
    skew = scipy.stats.skew(arr)
    kurt = scipy.stats.kurtosis(arr)
    
    features = list(hist) + [entropy, chi2, mean, std, skew, kurt]
    return features

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=1000)
    parser.add_argument('--output', type=str, required=True)
    args = parser.parse_args()

    classes = {
        'compressed': generate_compressed,
        'encrypted': generate_encrypted,
        'random': generate_random,
        'plaintext': generate_plaintext
    }

    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        header = [f'byte_{i}' for i in range(256)] + ['entropy', 'chi2', 'mean', 'std', 'skew', 'kurt', 'label']
        writer.writerow(header)

        for label, generator in classes.items():
            for _ in range(args.samples):
                data = generator()
                features = extract_features(data)
                writer.writerow(features + [label])

if __name__ == '__main__':
    main()
