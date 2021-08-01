import collections
import string

def count_letters(filename, case_sensitive=False):
    with open(filename, 'r') as f:
        original_text = f.read()
    if case_sensitive:
        alphabet = string.ascii_letters
        text = original_text
    else:
        alphabet = string.ascii_lowercase + string.digits + string.punctuation
        text = original_text.lower()
    alphabet_set = set(alphabet)
    counts = collections.Counter(c for c in text if c in alphabet_set)
    #counts = collections.Counter(c for c in text if c in alphabet )

    print("total:", sum(counts.values()))
    return counts

print(count_letters('file.txt'))
