from rsc.pe_parser import pe_parse
from rsc.pe_parser import dissasm
from rsc.format_parser import func_arg_parser
from rsc.argument_parser import py_ref_argparse
from rsc.html import export_to_html

import json

def main():
    parser = py_ref_argparse()
    args = parser.parse()

    print("Binary : ", args.binary)
    print("Arch   : ", args.arch)
    print("ABI    : ", args.abi)
    print("Lookback window: ", args.window)
    print("Format: ", args.format)
    print("Output: ", args.output)
    print("Functions path: ", args.functions)

    pe = pe_parse(args)
    section, code, text_rva = pe.get_text()
    imports = pe.parse_IAT()
    to_search = func_arg_parser(args.functions)


    entry_va = pe.binary.entrypoint
    imagebase = pe.binary.optional_header.imagebase
    entry_rva = entry_va - imagebase - text_rva

    dissasm_obj = dissasm(args, pe, code, entry_rva, text_rva, imports, to_search)
    data = dissasm_obj.search_args()

    if (args.format == "json"):
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(json.dumps(data, indent=4))
    else:
        export_to_html(data, args.output)

if __name__ == "__main__":
    main()