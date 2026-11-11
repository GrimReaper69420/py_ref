import json
from jinja2 import Template

# 1. The Jinja2 HTML Template
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Disassembly Report</title>
    <style>
        body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; padding: 20px; }
        h1 { color: #569cd6; border-bottom: 2px solid #569cd6; padding-bottom: 5px; }
        h2 { color: #4ec9b0; margin-top: 30px; border-bottom: 1px solid #333; }
        .call-block { background-color: #252526; border: 1px solid #333; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .call-header { color: #c586c0; font-weight: bold; margin-bottom: 10px; }
        .instruction-row { display: flex; padding: 2px 0; }
        .ins-index { color: #858585; width: 40px; }
        .ins-text { color: #dcdcaa; flex-grow: 1; }
        .ins-arg { color: #ce9178; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Disassembly Search Results</h1>

    {% for library_name, library in data.libraries.items() %}
        <h1>LIBRARY: {{ library_name }}</h1>

        {% for function_name, function_infos in library.functions.items() %}
            <h2>FUNCTION: {{ function_name }}</h2>

            {% for info in function_infos %}
                <div class="call-block">
                    <!-- Format the address using Jinja's string formatting -->
                    <div class="call-header">
                        [{{ loop.index0 }}] CALL: 0x{{ "%X" | format(info.call_address) }} | ARGS: {{ info.arg_count }}
                    </div>

                    {% if info.instructions %}
                        <div style="color: #9cdcfe; margin-bottom: 5px;">INSTRUCTIONS:</div>
                        
                        {% for instruction in info.instructions %}
                            <div class="instruction-row">
                                <span class="ins-index">[{{ "%02d" | format(loop.index0) }}]</span>
                                <span class="ins-text">{{ instruction }}</span>
                                
                                <!-- Find arguments that match this instruction index -->
                                {% set matched_args = info.arguments | selectattr("instruction_index", "equalto", loop.index0) | list %}
                                {% for arg in matched_args %}
                                    <span class="ins-arg">
                                        &nbsp;=====> ARG[{{ arg.arg_no }}] ({{ 'REG' if arg.is_register else 'STACK' }})
                                    </span>
                                {% endfor %}
                            </div>
                        {% endfor %}
                    {% endif %}
                </div>
            {% endfor %}
        {% endfor %}
    {% endfor %}
</body>
</html>
"""

def export_to_html(json_data: dict, output_file: str = "report.html"):
    """Renders the JSON data into a pretty HTML report."""
    # Load the template
    template = Template(html_template)
    
    # Render it with our dictionary
    html_output = template.render(data=json_data)
    
    # Save to disk
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_output)
    
    print(f"[+] Successfully exported HTML report to {output_file}")

# --- Example Usage ---
# Assuming 'searched_calls_dict' is the dictionary you got from dataclasses.asdict()
# export_to_html(searched_calls_dict, "disassembly_report.html")