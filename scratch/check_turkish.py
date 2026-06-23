import os
import re
import sys

# Turkish characters and common Turkish words (and their ASCII equivalents)
turkish_chars = re.compile(r'[ışğöçüİŞĞÖÇÜ]')
turkish_words = re.compile(
    r'\b(hata|basarili|sifre|kullanici|ayarlar|guncellendi|guncelle|sil|cihaz|tarama|rol|sistem|guvenlik|parola|posta|eposta|gonder|islem|kaydet|tamam|yetki|engellendi|aktif|pasif|tarih|durum|ipuc|ipucu|ekle|duzenle)\b', 
    re.IGNORECASE
)

exclude_dirs = {'.venv', '__pycache__', '.git', 'instance', '.gemini', 'scratch'}

def scan_files():
    results = []
    for root, dirs, files in os.walk('.'):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if not (file.endswith('.py') or file.endswith('.html') or file.endswith('.css') or file.endswith('.js')):
                continue
            
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except Exception as e:
                try:
                    with open(filepath, 'r', encoding='latin-1') as f:
                        lines = f.readlines()
                except Exception as e2:
                    results.append(f"Could not read {filepath}: {e2}")
                    continue
            
            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                # Check for non-ascii
                non_ascii = [c for c in clean_line if ord(c) > 127]
                
                # Check for common Turkish words
                word_match = turkish_words.search(clean_line)
                char_match = turkish_chars.search(clean_line)
                
                if non_ascii or word_match or char_match:
                    results.append(f"{filepath}:{line_idx}: {clean_line}")
                    
    with open('scratch/audit_results.txt', 'w', encoding='utf-8') as out:
        if results:
            for r in results:
                out.write(r + '\n')
        else:
            out.write("No potential Turkish text/characters found.\n")
    print(f"Audit completed. Results written to scratch/audit_results.txt. Found {len(results)} items.")

if __name__ == '__main__':
    scan_files()
