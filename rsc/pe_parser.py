import json
import argparse
import dataclasses
from pathlib import Path

# Parsers & Logger
from rsc.format_parser import func_arg_parser
from rsc.format_parser import VerboseLogger

# DataFormat for json
from rsc.format_parser import SearchedCalls, Library, FunctionInfo, Argument

# External modules import (Not-Builtin)
import lief
from tqdm import tqdm
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
from capstone.x86_const import *
from capstone.x86 import *

class pe_parse():
    def __init__(self, args):
        if not args.binary.is_file():
            raise FileNotFoundError(f"PE file not found: {args.binary.resolve()}")
        self.path = args.binary
        self.binary = lief.parse(str(self.path))

    def parse_IAT(self):
        imports = {}
        for imp in self.binary.imports:
            imports[imp.name] = dict()
            
            for entry in imp.entries:
                imports[imp.name][entry.name] = {
                    "rva": entry.iat_address,
                    "ordinal": entry.ordinal,
                }
        
        return imports
    
    def get_text(self):
        section = self.binary.get_section(".text")
        if section is None:
            raise RuntimeError(".text section not found")
        
        # image_base = self.binary.optional_header.imagebase
        text_rva = section.virtual_address

        # section.content is a list[int] in LIEF.
        code = bytes(section.content)
        return section, code, text_rva

    def optional_header_stats(self):
        return (
            self.binary.optional_header.imagebase
        )


######################################################################
#                          DISASSEMBLY CLASS                         #
######################################################################
class dissasm(VerboseLogger):

    # (NOTE) I declared the constants here
    DISSAM_X86_REG_MASK = {
        X86_REG_RCX: 1 << 0, X86_REG_ECX: 1 << 0, X86_REG_CX:  1 << 0, X86_REG_CL:  1 << 0, X86_REG_CH:  1 << 0,
        X86_REG_RDX: 1 << 1, X86_REG_EDX: 1 << 1, X86_REG_DX:  1 << 1, X86_REG_DL:  1 << 1, X86_REG_DH:  1 << 1,
        X86_REG_R8:  1 << 2, X86_REG_R8D: 1 << 2, X86_REG_R8W: 1 << 2, X86_REG_R8B: 1 << 2,
        X86_REG_R9:  1 << 3, X86_REG_R9D: 1 << 3, X86_REG_R9W: 1 << 3, X86_REG_R9B: 1 << 3,
    }

    COMMON_PROLOGUES = (
    # --- 32-bit (x86) ---
    b"\x55\x8b\xec",          # push ebp; mov ebp, esp (MSVC/GCC Standard)
    b"\x55\x89\xe5",          # push ebp; mov ebp, esp (GCC Alternative)
    b"\x8b\xff\x55\x8b\xec",  # mov edi, edi; push ebp; mov ebp, esp (Windows Hotpatch)
    
    # --- 64-bit (x64) ---
    b"\x55\x48\x89\xe5",      # push rbp; mov rbp, rsp (GCC Standard)
    b"\x40\x53\x48\x83\xec",  # push rbx; sub rsp, XX (MSVC Standard)
    b"\x48\x83\xec",          # sub rsp, XX (MSVC fastcall)
    b"\x48\x89\x5c\x24",      # mov [rsp+XX], rbx (MSVC Home space setup)
    b"\x48\x89\x4c\x24",      # mov [rsp+XX], rcx (MSVC Home space setup)
    )

    def __init__(self, args: argparse, pe: lief, text_bytes: bytes, offset: int, rva: int, imports: dict, to_search: func_arg_parser):
        super().__init__(args.verbose)

    # (NOTE) Inilializing the Capstone Engine, now we gonna use the arch & abi specified, else we gonna use X86_64
    # More arch to be added later on
    ###################################################################################################
        if (args.arch == "x86_64"): 
            self.mode = CS_MODE_64
            self.arch = CS_ARCH_X86
        elif (args.arch == "x86"):
            self.mode = CS_MODE_32
            self.arch = CS_ARCH_X86
        
        self.md = Cs(self.arch, self.mode)
        self.md.detail = True
    ###################################################################################################
        self.pe = pe
        self.text_bytes = text_bytes
        self.abi = args.abi
        self.parsed_IAT = imports
        self.rva = rva
        self.funcs = to_search
        self.window = args.window
        self.verbose = args.verbose

        # (NOTE) THis is the Searched calls struct
        self.call_args = SearchedCalls()
        
        # (NOTE) Creating a list of instructions
        self.instructions = self._disassemble(offset)

        # (NOTE) Validation of given function List & Finding all call sites
        self.call_sites = self._find_calls()
        self._validate_funcs()

    # Gonna fetch args for a specific Function in a lib
    def search_args(self):
        for lib, funcs in self.funcs.get_libraries().items():
            for func, data in funcs.items():
                self._search_args_single(lib, func, data.get("arg_no"))

        # If verbose is enabled I would pretty print the searched args        
        self.print_searched_calls(self.call_args)
        return dataclasses.asdict(self.call_args)

#######################################################################
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
#@@@@@@@@@@@@@@#########################################@@@@@@@@@@@@@@#
#@@@@@@@@@@@@@@#           Internal Functions          #@@@@@@@@@@@@@@#
#@@@@@@@@@@@@@@#########################################@@@@@@@@@@@@@@#
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#
#######################################################################
    def _disassemble(self, entry_offset=0):
        visited_offsets = set()
        instructions = {}
        text_len = len(self.text_bytes)
        
        queue = [entry_offset]
        linear_scan_ptr = 0

        with tqdm(
            total=text_len,
            desc="Disassembling (Recursive)",
            unit="B",
            disable=self.verbose < 1,
        ) as pbar:
            
            # Master loop: continues until Phase 2 confirms there are no more hidden functions
            while linear_scan_ptr < text_len:

                # ==========================================
                # PHASE 1: Recursive Descent (Drain the queue)
                # ==========================================
                while queue:
                    current_offset = queue.pop(0)
                    
                    # Follow the execution path until it stops or loops back on itself
                    while current_offset < text_len and current_offset not in visited_offsets:
                        chunk = self.text_bytes[current_offset : current_offset + 15]
                        
                        insn = next(
                            self.md.disasm(chunk, self.rva + current_offset, count=1),
                            None,
                        )
                        
                        # Stop execution path on invalid data
                        if insn is None:
                            visited_offsets.add(current_offset)
                            pbar.update(1)
                            break
                            
                        # Stop execution path on padding (INT3)
                        if insn.id == X86_INS_INT3:
                            for i in range(insn.size):
                                visited_offsets.add(current_offset + i)
                            pbar.update(insn.size)
                            break

                        # Mark EVERY byte of the valid instruction as visited to prevent desync
                        for i in range(insn.size):
                            visited_offsets.add(current_offset + i)
                            
                        instructions[current_offset] = insn
                        pbar.update(insn.size)

                        # --- Control Flow Analysis ---
                        is_jump = CS_GRP_JUMP in insn.groups
                        is_call = CS_GRP_CALL in insn.groups
                        is_ret = CS_GRP_RET in insn.groups

                        # Enqueue direct targets
                        if is_jump or is_call:
                            if len(insn.operands) > 0:
                                op = insn.operands[0]
                                if op.type == X86_OP_IMM:
                                    target_offset = op.imm - self.rva
                                    if 0 <= target_offset < text_len:
                                        if target_offset not in visited_offsets:
                                            queue.append(target_offset)

                        # Check for execution fall-through
                        if is_ret:
                            break 
                        if is_jump and insn.id == X86_INS_JMP:
                            break 
                            
                        current_offset += insn.size

                # ==========================================
                # PHASE 2: Gap-Finding (Heuristic Search)
                # ==========================================
                found_new_function = False
                
                while linear_scan_ptr < text_len:
                    if linear_scan_ptr in visited_offsets:
                        linear_scan_ptr += 1
                        continue
                    
                    # C-speed signature check against the unvisited gap
                    if self.text_bytes.startswith(dissasm.COMMON_PROLOGUES, linear_scan_ptr):
                        queue.append(linear_scan_ptr)
                        found_new_function = True
                        break
                    else:
                        # Treat unidentifiable bytes as data/padding
                        linear_scan_ptr += 1
                
                # If we scanned everything and found no new prologues, analysis is complete
                if not found_new_function:
                    break

        # Note: If the binary contains inline data, the progress bar will naturally 
        # stop before 100% because those bytes are correctly skipped.
        return [instructions[offset] for offset in sorted(instructions.keys())]

    # def _disassemble(self, offset=0):
    #     instructions = []
    #     text_len = len(self.text_bytes)

    #     with tqdm(
    #         total=text_len - offset,
    #         desc="Disassembling",
    #         unit="B",
    #         disable=self.verbose < 1,
    #     ) as pbar:

    #         while offset < text_len:
    #             old_offset = offset

    #             # Standard Python slice
    #             chunk = self.text_bytes[offset : offset + 15]

    #             insn = next(
    #                 self.md.disasm(
    #                     chunk,
    #                     self.rva + offset,
    #                     count=1,
    #                 ),
    #                 None,
    #             )

    #             # Invalid byte: skip 1 and keep sweeping
    #             if insn is None:
    #                 offset += 1
    #                 pbar.update(offset - old_offset)
    #                 continue

    #             # Skip INT3 padding
    #             if insn.id == X86_INS_INT3:
    #                 offset += insn.size
    #                 pbar.update(offset - old_offset)
    #                 continue

    #             instructions.append(insn)

    #             offset += insn.size
    #             pbar.update(offset - old_offset)

    #     return instructions

    def _search_args_single(self, lib: str, func: str, arg_no: int):
        func_data = FunctionInfo()

        iat_rva = self.funcs.get_rva(lib, func)
        self.log(f"IAT rva: {iat_rva:#X}")
        
        for call_site in self.call_sites:
            # print(f"call_site Address: {call_site.get('address'):#X}")
            if(call_site.get('target') == iat_rva):
                index = call_site.get("index")
                start = max(0, index - self.window)
                instruction_window = self.instructions[(start): (index+1)][::-1]

                # No X86_64 we just gonna go fastcall
                if ( (self.arch == CS_ARCH_X86) and (self.mode == CS_MODE_64) ):
                    func_data = self._parse_inst_X86_64_fastcall(instruction_window, func, arg_no)

                elif ( (self.arch == CS_ARCH_X86) and (self.mode == CS_MODE_32) ):
                    # Imma handle cdecl and stdcall the same, these niggas only differ in stack cleanup
                    if ( (self.abi == "cdecl") or (self.abi == "stdcall") ):
                        func_data = self._parse_inst_X86_cdecl_stdcall(instruction_window, func, arg_no)
                    elif (self.abi == "thiscall"):
                        self.log("Not Supported Yet :<")
                        pass
                
                # ADDUNg the function info at the end
                self.call_args.add_function_info(
                    library_name=lib,
                    function_name=func,
                    function_info=func_data
                )


##############################################################
#               ARGUMENT PASSING FUNCTIONS                   #
##############################################################

    ###############################
    #           X 86              #
    ###############################

    def _parse_inst_X86_cdecl_stdcall(self, inst_window: list[bytes], func: str, arg_no: int):
        func_data = FunctionInfo(
            call_address=inst_window[0].address,
            arg_count=arg_no,
            )
        arg_count = 0
        first_call = True

        for index, instruction in enumerate(inst_window):
            addr     = instruction.address
            mnemonic = instruction.mnemonic
            op_str   = instruction.op_str
            operands = instruction.operands
            
            line = f"{addr:#X}: {mnemonic} {op_str}"
            func_data.instructions.append(line)
            
            if (mnemonic == "push") and (arg_count != arg_no):
                arg = Argument(
                    arg_no=arg_count,
                    is_register=False,
                    instruction_index=index
                )
                func_data.arguments.append(arg)
                arg_count += 1
                continue
            
            # Stop DOing function arg analysis if call Found
            elif(mnemonic == "call")  and (arg_count != arg_no) and (not first_call):
                arg_count = arg_no
            elif(first_call):
                first_call = False

        return func_data

    def _parse_inst_X86_64_fastcall(self, inst_window: list[bytes], func: str, arg_no: int):
        func_data = FunctionInfo(
            call_address=inst_window[0].address,
            arg_count=arg_no,
        )
        # This visited mask is for the REgiteres visited and set to register bit
        visited_mask = 0
        reg_count = 0
        stack_count = 0
        first_call = True
        shadow_dis = dict()

        for index, instruction in enumerate(inst_window):
            addr     = instruction.address
            mnemonic = instruction.mnemonic
            op_str   = instruction.op_str
            operands = instruction.operands

            line = f"{addr:#X}: {mnemonic} {op_str}"
            func_data.instructions.append(line)

            if (operands[0].type == X86_OP_REG) and (arg_no > 0):
                reg = operands[0].reg
                reg_bit_mask = dissasm.DISSAM_X86_REG_MASK.get(reg)
                if (reg_bit_mask) and (reg_count < 4):
                    already_visited = (visited_mask & reg_bit_mask) != 0
                    if (already_visited):
                        continue

                    arg_number = reg_bit_mask.bit_length() - 1
                    visited_mask |= reg_bit_mask
                    arg = Argument(
                        arg_no=arg_number,
                        is_register=True,
                        instruction_index=index
                    )
                    func_data.arguments.append(arg)
                    reg_count += 1
                    arg_no -= 1
            
            elif ( (instruction.mnemonic == "mov") and (operands[0].type == X86_OP_MEM) and (arg_no > 0) ):
                mem = operands[0].mem
                if ( (mem.base  == X86_REG_RSP) and (mem.index == X86_REG_INVALID) and (mem.scale == 1) ):
                    disp = mem.disp
                    if disp >= 0x20 and (disp - 0x20) % 8 == 0:
                        arg_number = 4 + ((disp - 0x20) // 8)
                        arg = Argument(
                            arg_no=arg_number,
                            is_register=False,
                            instruction_index=index
                        )
                        func_data.arguments.append(arg)
                        arg_no -= 1

            elif( (instruction.mnemonic == "push") and (arg_no > 0) ):
                arg = Argument(
                        arg_no=(stack_count + 4),
                        is_register=False,
                        instruction_index=index
                    )
                func_data.arguments.append(arg)
                stack_count += 1
                arg_no -= 1
            
            # Stop DOing function arg analysis if call Found
            elif(mnemonic == "call") and (not first_call):
                arg_no = 0
            elif(first_call):
                first_call = False

        return func_data
#############################################################################################################################################


    def _find_calls(self):
        calls = []
        for i, insn in enumerate(self.instructions):
            if insn.mnemonic != "call":
                continue

            target = self._resolve_call_target(insn)

            call = {
                "index": i,
                "address": insn.address,
                "target": target,
                "indirect": (
                    bool(insn.operands)
                    and insn.operands[0].type == X86_OP_MEM
                ),
                "instruction": insn,
            }

            calls.append(call)

        return calls


    def _resolve_call_target(self, insn):
        if not insn.operands:
            return None

        preffered_base = self.pe.optional_header_stats()
        op = insn.operands[0]

        # Direct calls
        if op.type == X86_OP_IMM:
            return op.imm

        if op.type == X86_OP_MEM:
            mem = op.mem
            # Memory-based call target address calculation
            if mem.base == X86_REG_RIP:
                return insn.address + insn.size + mem.disp
            
            # Memory Direct Displacement Calls
            if ( mem.base == X86_REG_INVALID and mem.index == X86_REG_INVALID ):
                return (mem.disp - preffered_base)

        # Inderect and other calls
        return None

    def _validate_funcs(self):
        for library, funcs in self.funcs.get_libraries().items():
            for func in funcs:
                if self.parsed_IAT.get(library, {}).get(func, {}):
                    self.funcs.set_is_here(library, func, True)
                    self.funcs.set_rva(library, func, self.parsed_IAT.get(library).get(func).get('rva', {}))
        
        # (NOTE) Now we gonna deacclocate the self.parsed_IAT
