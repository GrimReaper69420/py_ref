import argparse
import json
from pathlib import Path

class py_ref_argparse():
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="py_ref",
            description="Binary parser to fetch all the Library procedure calls"
        )

        self._add_arguments()

# (NOTE) Main Parser Function
    def parse(self):
        args = self.parser.parse_args()
        config = self._load_config(args.config)
        args = self._apply_defaults(args, config)
        self._validate(args, config)

        return args

# (NOTE) Helper Functions
    # Adding arguments to the parser
    def _add_arguments(self):
        self.parser.add_argument(
            "--config",
            type=Path,
            default=Path("./rsc/config.json"),
            help="Path to configuration file"
        )

        self.parser.add_argument(
            "-b",
            "--binary",
            type=Path,
            help="Path to PE binary",
            required=True,
        )

        self.parser.add_argument(
            "--arch",
            help="Architecture of the binary IE. x86, x86_64, aarch64"
        )

        self.parser.add_argument(
            "--abi",
            help="ABI for calling convention Analysis"
        )

        self.parser.add_argument(
            "-f",
            "--format",
            choices=["html", "json"],
            help="Output format"
        )

        self.parser.add_argument(
            "-funcs",
            "--functions",
            type=Path,
            help="Functions for which Xrefs to be Found",
            required=True,
        )

        self.parser.add_argument(
            "-o",
            "--output",
            type=Path,
            help="Output path"
        )

        self.parser.add_argument(
            "-w",
            "--window",
            type=int,
            help="Look back window, for the number of instructions to look behind to find arguments"
        )

        self.parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Enable verbose output"
        )

    # Loading the config FIle
    def _load_config(self, path):
        if not path.exists():
            self.parser.error(
                f"Config file does not exist: {path}"
            )

        try:
            with path.open("r") as f:
                return json.load(f)

        except json.JSONDecodeError as e:
            self.parser.error(
                f"Invalid JSON in {path}: {e}"
            )

    # Apply the defualt config if specified
    def _apply_defaults(self, args, config):
        defaults = config.get("defaults", {})

        if args.arch is None:
            args.arch = defaults.get("arch")

        if args.abi is None:
            args.abi = defaults.get("abi")

        if args.format is None:
            args.format = defaults.get("format")

        if args.window is None:
            args.window = defaults.get("window")

        if args.output is None:
            args.output = Path(
                defaults.get("output", "./output." + args.format)
            )

        return args
    
# (NOTE) ##### TO VALIDATE ARGS according to COnfig
    def _validate(self, args, config):
        architectures = config.get("architectures", {})

        # Verifying the Arch is supported
        if args.arch not in architectures:
            self.parser.error(
                f"Unsupported architecture: {args.arch}"
            )
        
        # Verifying the API's Supported for that arch
        arch_config = architectures[args.arch]
        allowed_abis = arch_config.get("abis", [])

        if args.abi not in allowed_abis:
            self.parser.error(
                f"ABI '{args.abi}' is not supported "
                f"for architecture '{args.arch}'. "
                f"Allowed: {allowed_abis}"
            )