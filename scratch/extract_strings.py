import ast

def extract_strings(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=filepath)
    
    strings = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append((node.lineno, node.value))
        # Support older python ast variations if needed
        elif isinstance(node, ast.Str):
            strings.append((node.lineno, node.s))
            
    # Sort by line number
    strings.sort(key=lambda x: x[0])
    
    with open('scratch/extracted_app_strings.txt', 'w', encoding='utf-8') as out:
        for lineno, val in strings:
            # Clean string for representation
            repr_val = repr(val)
            if len(repr_val) > 100:
                repr_val = repr_val[:100] + '... [TRUNCATED]'
            out.write(f"Line {lineno}: {repr_val}\n")

if __name__ == '__main__':
    extract_strings('app.py')
    print("Extracted strings written to scratch/extracted_app_strings.txt")
