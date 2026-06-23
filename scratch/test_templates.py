import os
from jinja2 import Environment, FileSystemLoader

templates_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
print("Templates directory:", templates_dir)

env = Environment(loader=FileSystemLoader(templates_dir))

# Add mock filters to environment to prevent UndefinedError on compilation (though syntax check won't run filters, we can just compile)
env.filters['scan_name'] = lambda x: x
env.filters['localtime'] = lambda x: x

for filename in os.listdir(templates_dir):
    if filename.endswith(".html"):
        filepath = os.path.join(templates_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            env.parse(source)
            print(f"OK: {filename}")
        except Exception as e:
            print(f"ERROR in {filename}: {e}")
