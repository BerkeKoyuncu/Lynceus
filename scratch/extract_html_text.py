import os
from html.parser import HTMLParser

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_nodes = []
        self.in_script_or_style = False

    def handle_starttag(self, tag, attrs):
        if tag in ['script', 'style']:
            self.in_script_or_style = True
        
        # Check all attributes for common user-visible strings (like placeholders, values, title, alt)
        for attr, val in attrs:
            if attr in ['placeholder', 'title', 'alt', 'value'] and val:
                # Include standard jinja variables check
                if not (val.startswith('{{') and val.endswith('}}')):
                    self.text_nodes.append(f"[ATTR:{attr}] {val}")

    def handle_endtag(self, tag):
        if tag in ['script', 'style']:
            self.in_script_or_style = False

    def handle_data(self, data):
        if self.in_script_or_style:
            return
        clean_data = data.strip()
        if clean_data and not (clean_data.startswith('{%') or clean_data.startswith('{#') or clean_data.startswith('{{') or clean_data.startswith('<!')):
            self.text_nodes.append(clean_data)

def extract_html_texts():
    exclude_files = {'decoy_wp.html'} # We know decoy WP login is OK
    out_lines = []
    
    for file in sorted(os.listdir('templates')):
        if not file.endswith('.html') or file in exclude_files:
            continue
        
        filepath = os.path.join('templates', file)
        out_lines.append(f"=== {file} ===")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        parser = TextExtractor()
        parser.feed(html_content)
        
        for text in parser.text_nodes:
            out_lines.append(f"  {text}")
            
    with open('scratch/extracted_html_text.txt', 'w', encoding='utf-8') as out:
        out.write('\n'.join(out_lines))
    print("HTML text extraction complete. Saved to scratch/extracted_html_text.txt")

if __name__ == '__main__':
    extract_html_texts()
