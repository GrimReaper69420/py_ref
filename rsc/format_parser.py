import json
import logging
from dataclasses import dataclass, field

class func_arg_parser:
    def __init__(self, json_file):
        with open(json_file, "r", encoding="utf-8") as file:
            self._libraries = json.load(file)

# (NOTE) Setting is_here all to false, as need this for disassebmler obj and what not
# (NOTE) Also gonna set RVA to make the disassembler easy
            for functions in self._libraries.values():
                for function in functions.values():
                    function["is_here"] = False
                    function["rva"] = 0x0

    def get_libraries(self):
        """Get the complete parsed JSON."""
        return self._libraries

    def get_functions(self, library):
        return self._libraries.get(library, {})
    
    
    def get_function(self, library, function):
        return self._libraries.get(library, {}).get(function)
    
    
    def get_arg_no(self, library, function):
        function_data = self.get_function(library, function)
        if function_data is None:
            return None

        return function_data.get("arg_no")

    def get_is_here(self, library, function):
        function_data = self.get_function(library, function)
        if function_data is None:
            return None

        return function_data.get("is_here")


    def get_rva(self, library, function):
        function_data = self.get_function(library, function)
        if function_data is None:
            return None

        return function_data.get("rva")


    def set_function_data(self, library, function, data):
        """Set/update function data."""
        self._libraries[library][function] = data

    def set_arg_no(self, library, function, arg_no):
        """Set/update argument count."""
        self._libraries[library][function]["arg_no"] = arg_no

    def set_is_here(self, library, function, is_here):
        self._libraries[library][function]["is_here"] = is_here

    def set_rva(self, library, function, rva):
        self._libraries[library][function]["rva"] = rva

@dataclass
class Argument:
    arg_no: int
    is_register: bool
    instruction_index: int


@dataclass
class FunctionInfo:
    call_address: int = 0
    arg_count: int = 0
    arguments: list[Argument] = field(default_factory=list)
    instructions: list = field(default_factory=list)

@dataclass
class Library:
    name: str
    functions: dict[str, list[FunctionInfo]] = field(default_factory=dict)

    def add_function_info(
        self,
        function_name: str,
        function_info: FunctionInfo,
    ):
        self.functions.setdefault(function_name, []).append(function_info)

@dataclass
class SearchedCalls:
    libraries: dict[str, Library] = field(default_factory=dict)

    def get_library(self, library_name: str) -> Library:
        if library_name not in self.libraries:
            self.libraries[library_name] = Library(library_name)

        return self.libraries[library_name]

    def add_function_info(
        self,
        library_name: str,
        function_name: str,
        function_info: FunctionInfo,
    ):
        library = self.get_library(library_name)
        library.add_function_info(function_name, function_info)



class VerboseLogger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def log(self, message: str):
        if self.verbose:
            print(f"[+] {message}")

    def print_searched_calls(self, searched_calls):
        if not self.verbose:
            return
        
        for library_name, library in searched_calls.libraries.items():
            self.log("")
            self.log("=" * 70)
            self.log(f"LIBRARY: {library_name}")
            self.log("=" * 70)

            for function_name, function_infos in library.functions.items():
                self.log("")
                self.log(f"FUNCTION: {function_name}")
                self.log("-" * 70)

                for index, info in enumerate(function_infos):
                    self._print_function_info(function_name, index, info)

    def _print_function_info(self, function_name: str, index: int, info):
        self.log(
            f"   [{index}] "
            f"CALL: {self._format_address(info.call_address)} "
            f"ARGS: {info.arg_count}"
        )

        if info.instructions:
            self.log("   INSTRUCTIONS:")
            for instruction_index, instruction in enumerate(info.instructions):
                # Use the new shared formatter
                formatted_instruction = self._format_instruction(
                    instruction_index,
                    instruction,
                    info.arguments,
                )
                self.log(formatted_instruction)
        self.log("")

    def _format_instruction(self, instruction_index: int, instruction: str, arguments: list) -> str:
        output = (
            f"    [{instruction_index:02d}] "
            f"{instruction}"
        )

        for argument in arguments:
            if argument.instruction_index != instruction_index:
                continue

            arg_type = "REG" if argument.is_register else "STACK"
            output += f"  =====> ARG[{argument.arg_no}] ({arg_type})"

        return output

    @staticmethod
    def _format_address(address: int) -> str:
        return f"0x{address:X}"