from yapsy.IPlugin import IPlugin
from operator import itemgetter
from core.api import Api

#from core.ef_parser import efParserClass, disasm_parsed
#import core.vmp_regex as vmr #import VMP_Regex
#from cleanVT.ef_parser import efParserClass #disasm_parsed, efParserClass
#import cleanVT.ef_parser

from cleanVT.dcr import dead_code_remover
from cleanVT.fx64_ef_parser import efParserClass, disasm_parsed
from cleanVT.fx64_patterns import REGEXPATTERNS
from cleanVT.fx64_operands import *
from cleanVT.mymapping import *

import re
import hashlib



 
'''
class VMP_addrlist:
    def __init__(self):
        self.linked_dict = {}
        self.two_address_buf = []
        self.temp_buf = {}
        self.runOnce = False
        self.dup_filter = {}

        self.filtered_dict = {}
        self.count = 0

    def transfer(self):
        #print(len(self.linked_dict))
        for addr in self.linked_dict:
            for pair in self.linked_dict[addr]:
                self.filtered_dict[addr][0][pair[0]] = 0 
                self.filtered_dict[addr][1][pair[1]] = 0 


    def init_storage_list(self, this_addr):
        self.linked_dict[this_addr] = list()
        self.filtered_dict[this_addr] = (dict(), dict())  

    def get_prev_executed(self, addr):
        return self.linked_dict[addr][0]
    
    def get_next_executed(self, addr):
        return self.linked_dict[addr][1]
    
    def get_storage_list_size(self):
        return len(self.linked_dict)

    def get_list(self, curr_addr):
        return self.linked_dict[curr_addr]

    def key_addr_exists(self, key_addr):
        if key_addr in self.linked_dict:
            return True
        
        return False
    
    def map_addrs(self, curr_addr, before_or_after):
        self.temp_buf[self.two_address_buf[before_or_after]] += " " # add space from first addr and 2nd to indicate next addr
        self.temp_buf[self.two_address_buf[before_or_after]] += curr_addr # so we have some_addr curr_addr
        self.temp_buf[curr_addr] = self.two_address_buf[before_or_after]


    def output(self):
        for address in self.filtered_dict:
            print(f"TARGET address: {address} executed --------------")
            for entry in self.filtered_dict[address][0]:
                print(f"executed before: {entry}")
            print("end before ---------------------------------------\n\n")
            for after in self.filtered_dict[address][1]:
                print(f"executed after: {after}")
            print("--------------------------------------after done. \n\n")

    def map_addrs_and_reset(self, curr_addr, before_or_after):
        self.map_addrs(curr_addr, before_or_after)

        self.try_copy_to_main(before_or_after)

        if before_or_after == 1:
            self.two_address_buf.clear()

        self.two_address_buf.append(curr_addr)
    
    def try_copy_to_main(self, before_or_after):
        addr = self.two_address_buf[before_or_after]
        
        ba_list = self.temp_buf[addr].split()
        if len(ba_list) == 2:
            self.linked_dict[addr].append((ba_list[0], ba_list[1]))
            self.temp_buf[addr] = ""

    def get_pair_of_addr(self, addr):
        if addr not in self.filtered_dict:
            print(addr)
            print("ruhroh big error")
            return
        temp_before = list()
        temp_after = list()
        for entry in self.filtered_dict[addr][0]:
            temp_before.append(entry)
        for after in self.filtered_dict[addr][1]:
            temp_after.append(after)

        return (temp_before, temp_after)
        

    def process_data(self, curr_addr):
        if curr_addr not in self.linked_dict: #if curr_addr isn't an entry of linked_dict, make a list.
            if self.get_storage_list_size() == 0:
                self.runOnce = True
            self.init_storage_list(curr_addr) # linked_dict[curr_addr] = list()

        if self.runOnce: # @ very beginning, there's no addr before so mark w/ -1.
            self.temp_buf[curr_addr] = "-1 " # if this is 1st time we see curr_addr, ie, runOnce, then there was no address prior to this.
            self.two_address_buf.append(curr_addr) # add addr to list.
            self.runOnce = False
        
        else:

            if len(self.two_address_buf) == 2:   # if list has 2 entries, 
                self.map_addrs_and_reset(curr_addr, 1) # second addr entry
            else:
                self.map_addrs_and_reset(curr_addr, 0)  # first addr entry
'''


     
class track_stack:
    def __init__(self, starting_size):
        self.display_limit = 20
        self.fake_stack = []
        self.off_from_csp = []
        self.fake_sp = 0
        self.setup_fake(starting_size)
        self.ret_addr_num = 0

    def adjust_stack_if_needed(self, move_len, op_type):

        return
    
    def move_sp(self, move_len, op_type):
        decimal_form = int(move_len, 0)
        n_bytes = int(decimal_form/8)
        print(n_bytes)
        if op_type == "sub": 
            self.fake_sp += n_bytes
            while self.fake_sp + 1 > len(self.fake_stack):
                self.fake_stack.append("0")
        elif op_type == "add":
            self.fake_sp -= n_bytes
        else:
            print("uhoh")

    def setup_fake(self, size):
        #for x in range(0, size):
        #    self.fake_stack.append("0")
        self.fake_stack.append("'stack' trace's starting point")
        #self.fake_stack[self.fake_sp] = "at start"
        
        
    
    def fake_push(self, data):
        self.fake_sp += 1
        if self.fake_sp < len(self.fake_stack):   # 'stack' has enough space?
            
            self.fake_stack[self.fake_sp] = data + "_" + str(self.ret_addr_num)
        else:   # passed our 'limit'. 
            self.fake_stack.append(data)
            #self.fake_sp += 1
            print(f"sp: {self.fake_sp} type: {type(self.fake_sp)} pstack len: {len(self.fake_stack)}\n pstack: {self.fake_stack}")
            
        
        
            
    
    def fake_pop(self):
        if self.fake_sp >= 0: 
            data = self.fake_stack[self.fake_sp]
            self.fake_stack[self.fake_sp] = data
            if self.fake_sp != 0:
                self.fake_sp -= 1
            else:
                print("at 'end' of stack...")
                

            return data

        #return data
    
    def fake_call(self):
        data_to_push = "return addr"  
        self.fake_push(data_to_push)
        self.ret_addr_num += 1

    
    def corresponding_fake_offset(self, offset):
        fake_offset = int(offset, 0)
        move_len = fake_offset >> 3
    
    def offsets_from_curr_sp(self):
        self.off_from_csp.clear()

        top_distance = self.fake_sp 

        for i in range(0, top_distance):
            hex_form = hex(8*(top_distance - i))
            self.off_from_csp.append("current_sp + " + hex_form)
        for j in range(top_distance, len(self.fake_stack)):
            off = j - top_distance
            as_hex = hex(8*(off))
            self.off_from_csp.append("current_sp - " + as_hex)

    
    def output(self):
        print("\n\n------")

        hex_form = ""
        hex_sp = ""
        self.offsets_from_curr_sp()

        for pos in range(0, len(self.fake_stack)):
            hex_form = hex(8*pos)
            if self.fake_sp == pos:
                hex_sp = hex(8*pos)
                output_str = "stack pointer --->" + "|" + self.fake_stack[pos] + "| " #+ self.off_from_csp[pos]
            else:
                
                output_str = "start rsp - " + hex_form + ": |" + self.fake_stack[pos] + "| " + self.off_from_csp[pos]
            
            if (len(self.fake_stack) <= 2*self.display_limit) or (len(self.fake_stack) > 2*self.display_limit and \
                (self.fake_sp - pos >= -(self.display_limit)) and \
                self.fake_sp - pos <= self.display_limit):
                print(output_str)
        print("------\n\n")
        #print(f"SP @ hex#: {hex_sp} fake SP: {self.fake_sp} len: {len(self.fake_stack)}" )
        
    def reset(self):
        self.fake_stack.clear()
        self.fake_sp = 0

class unique_block: 
    def __init__(self, disasm_lines, bID = -1, starting_addr = "", hash = ""):
        self.instructions = disasm_lines.copy()
        self.block_ID = bID
        self.start_of_block_addr = starting_addr
        self.hash_of_block = hash
        self.block_len = len(self.instructions)
    
    def get_ID(self):
        return self.block_ID
    
    def get_start_address(self):
        return self.start_of_block_addr
    
    def get_hash_of_block(self):
        return self.hash_of_block
    
    def get_disasm_lines(self):
        return self.instructions
        

class ub_archive: 
    def __init__(self):
        
        self.similar_leads_dict = {}
        self.instruction_blocks_dict = {} # provide addr, get ublock
        self.hashes_of_blocks = {}  # provide addr, get hash
        self.blocks_ID_dict = {}    # provide addr, get ID 
        self.hashed_blocks = {}     # provide hash, get addr

        self.address_of_block_id_list = []          # provide id, get address

        self.execution_order_of_every_ub_list = []  # provided id, get address
        self.id_count = 0   # how many block_IDs are there?
    
    def get_ublock_from_address(self, block_address):
        return self.instruction_blocks_dict[block_address]
    
    def get_ublock_id_from_address(self, block_address):
        return self.blocks_ID_dict[block_address]

    def get_ublock_address_from_id(self, block_id):
        if block_id < len(self.address_of_block_id_list): # prevent out ob bounds
            return self.address_of_block_id_list[block_id]
        
        return None

    def get_hash_from_address(self, block_address):
        return self.hashes_of_blocks[block_address]

    def print_blocks(self):
        for addr in self.instruction_blocks_dict:
            print(f"addr: {addr} block id: {self.blocks_ID_dict[addr]} instructions: {self.instruction_blocks_dict[addr].instructions}\n")
    
    def output_stats(self):
        print(f"len of ub_order list: {len(self.execution_order_of_every_ub_list)}\n")
        print(f"len of similar_leads dict [should be empty]: {len(self.similar_leads_dict)}\n")
        print(f"len of instruction_blocks_dict: {len(self.instruction_blocks_dict)}\n")
        print(f"len of blocks_ID dict : {len(self.blocks_ID_dict)}\n")
        print(f"len of addr_of_block_id list : {len(self.address_of_block_id_list)}\n")
        print(f"num of blocks: {(self.id_count)}\n")

        #for addr in self.blocks_ID_dict:
        #    print(f"Block ID: {self.blocks_ID_dict[addr]} address: {addr}\n")
        #    print(f"Block content: {self.instruction_blocks_dict[addr].instructions}\n")
        self.distinct_addrs = {}
         
        
        for x in range(0, len(self.execution_order_of_every_ub_list)):
            tmp_addr = self.execution_order_of_every_ub_list[x][0]
            #print(f"addr: {x}\n")
            if tmp_addr in self.instruction_blocks_dict:
                print(f"addr: {tmp_addr} Block ID: {self.blocks_ID_dict[tmp_addr]} {self.instruction_blocks_dict[tmp_addr].instructions} rows: {self.execution_order_of_every_ub_list[x][1]}\n")
            #print(f"address: {tmp_addr} block ID: {self.blocks_ID_dict[tmp_addr]}  count: {self.distinct_addrs[tmp_addr]}{self.instruction_blocks_dict[tmp_addr].instructions} rows: {self.execution_order_of_every_ub_list[x][1]}")
            #print(f"{x}th unique block: addr = {tmp_addr}\nUB_ID:{self.blocks_ID_dict[tmp_addr]} rows: {self.execution_order_of_every_ub_list[x][1]}")

    def keep_track(self, ub_addr, line_nums):
        self.execution_order_of_every_ub_list.append((ub_addr, line_nums.copy()))
        

    def is_encountered_block(self, ub_addr):
        return ub_addr in self.instruction_blocks_dict and ub_addr in self.blocks_ID_dict
 

    def create_entries(self, ub, id):
        ub_addr = ub.get_start_address()
        hash_of_ub = ub.get_hash_of_block()

        if hash_of_ub not in self.hashed_blocks:
            self.hashed_blocks[hash_of_ub] = []
        self.hashed_blocks[hash_of_ub].append(ub_addr)

        self.hashes_of_blocks[ub_addr] = hash_of_ub

        self.instruction_blocks_dict[ub_addr] = ub
        self.blocks_ID_dict[ub_addr] = id
        self.address_of_block_id_list.append(ub_addr)
        
        
   
    
    def get_id_count(self):
        return self.id_count
    
    def update_id_count(self):
        self.id_count += 1


class mapped_trace:
    def __init__(self, tracelen):

        self.the_parser = efParserClass()


        self.every_executed_addr_data_list = [] # list of 3-tuples corresponding to: (RIP, reg values post execution, memory val [if applicable])
        self.every_disasm_parsed_dict = {}
        self.execution_count_of_addr_dict = {}
        self.disasm_history_dict = {}

        self.nth_line = []

        self.trace_len = tracelen
        self.total_read = 0
    
    def get_parsed_obj_of_line(self, disasm_line):

        if disasm_line in self.every_disasm_parsed_dict: 

            return self.every_disasm_parsed_dict[disasm_line]

        return None
    
    def get_entry_from_every_executed_addr_data(self, nth_entry):
        if len(self.every_executed_addr_data_list) > 0 and nth_entry < len(self.every_executed_addr_data_list):
            return self.every_executed_addr_data_list[nth_entry]

    def at_end_of_trace(self):
        if self.trace_len - self.total_read == 0:
            return True

        return False
    
    def log_all_executed_addr_data(self, executed_address, register_values, memory_value):
        self.every_executed_addr_data_list.append((executed_address, register_values, memory_value))

        self.nth_line.append(self.total_read)  

        self.total_read += 1
    
    def log_instr_of_all_unique_addrs(self, executed_address, instr_string):
        self.disasm_history_dict[executed_address] = instr_string
    
    def parse_unique_lines(self, instr_string, opc_bytes):
        if re.search(r'xmm', instr_string):
            self.every_disasm_parsed_dict[instr_string] = None
            print(f"SSE stuff not implemented.. not parsing... {instr_string}")
        elif re.search(r'ymm', instr_string):
            self.every_disasm_parsed_dict[instr_string] = None
            print(f"SSE stuff not implemented.. not parsing... {instr_string}")
        else:
            if instr_string not in self.every_disasm_parsed_dict:
                self.every_disasm_parsed_dict[instr_string] = disasm_parsed()
                self.the_parser.complete_parse(instr_string)
                parsed = self.the_parser.copy()
                self.every_disasm_parsed_dict[instr_string].set_operator(parsed[0])
                self.every_disasm_parsed_dict[instr_string].operand_count = (parsed[1])
                self.every_disasm_parsed_dict[instr_string].operand_list = (parsed[2])
                self.every_disasm_parsed_dict[instr_string].set_opcodes(opc_bytes)
                self.the_parser.reset()

class ub_builder: 
    def __init__(self):
        self.new_block = False
        self.final_hash_set = False
        self.associated_block_hash = ""
        self.start_address = ""
        self.bb_instr = []
    
    def create_ub(self, blockid):
        return unique_block(self.bb_instr, blockid, self.start_address, self.associated_block_hash)

    def get_block_address(self):
        return self.start_address
    
    def get_current_hash(self):
        return self.associated_block_hash

    def md5_hash(self, message):
        if type(message) is not bytes:
            message = message.encode()

        hashed = hashlib.md5(message)

        return hashed.hexdigest()
    
    def set_new_block_state(self, state):
        self.new_block = state
    
    def get_new_block_state(self):
        return self.new_block
    
    def is_block_empty(self):

        if len(self.bb_instr) == 0:
            return True

        return False
    
    def mark_start_of_block(self, starting_addr):
        self.start_address = starting_addr
    
    def add_line_to_block(self, instr_string):
        self.bb_instr.append(instr_string)

        self.hash_lines(instr_string)

    def hash_lines(self, instr_string):
        self.associated_block_hash += self.md5_hash(instr_string)

    def hash_completed_block(self):

        if not self.final_hash_set:
            self.associated_block_hash = self.md5_hash(self.associated_block_hash)
            self.final_hash_set = True

    def reset_hash(self):
        self.associated_block_hash = ""
    def cleanup(self):
        self.bb_instr.clear()
        self.reset_hash()
        self.final_hash_set = False
    
    def reset(self):
        self.new_block = False
        self.cleanup()

class cVMP_Regex:

    def __init__(self, t_len = 0):


        self.trace_map = mapped_trace(t_len)
        self.first_pass_archive = ub_archive()
        self.second_pass_archive = ub_archive()

        self.the_builder = ub_builder()

        self.pstack = track_stack(1024)

        self.the_cleaner = dead_code_remover()
        
        self.aliases = {}
        self.branches = {}
        self.destinations = {}
        self.init_branches()
        self.missed = {}

        self.groups = {}
        self.groups["jmp"] = []
        self.handlers = {}
        
    
    def output_to_file(self, some_list, filename):
        try:
            with open(filename, "w") as f:
                for ln in some_list:
                    f.write(ln + "\n")
        except:
            print("ruhroh")
    
    def init_branches(self):
        self.branches['ja'] = 0
        self.branches['jb'] = 0
        #self.branches['jc'] = 0
        self.branches['je'] = 0
        self.branches['jg'] = 0
        self.branches['jl'] = 0
        self.branches['jle'] = 0
        #self.branches['jo'] = 0
        self.branches['js'] = 0
        self.branches['jp'] = 0
        self.branches['jz'] = 0
        self.branches['jnae'] = 0
        self.branches['jne'] = 0
        self.branches['jnb'] = 0
        self.branches['jnz'] = 0
        self.branches['jnge'] = 0
        self.branches['jnc'] = 0
        self.branches['jnbe'] = 0
        self.branches['jnl'] = 0
        self.branches['jnle'] = 0
        self.branches['jpe'] = 0
        self.branches['call'] = 0
        self.branches['ret'] = 0
        self.branches['jmp'] = 0
        
        
        self.branches['jae'] = 0
        self.branches['jnp'] = 0
        
        self.branches['jns'] = 0
        self.branches['jno'] = 0
        
        self.branches['jbe'] = 0
        
        self.branches['jge'] = 0
        self.branches['jna'] = 0
    

    def filter_addr_range(self, start_addr, end_addr, instr_string, current_addr, values_of_registers, memory_val, op_codes):
        if current_addr >= start_addr and current_addr <= end_addr:
            self.process_into_blocks(instr_string, hex(current_addr)[2:], values_of_registers, memory_val, op_codes)
    
    def testoutputold(self, filename):
        try:
            with open(filename, "w") as f:

                f.write(f"Total unique blocks: {len(self.second_pass_archive.instruction_blocks_dict)}\n")
                f.write(f"                                                                       |\n")
                f.write(f"                                                                       |\n")
                f.write(f"                                                                       |\n")
                f.write(f"                                                                       |\n")
                f.write(f"------------------------------------------------------------------------\n\n")

                for x in range(0, len(self.second_pass_archive.execution_order_of_every_ub_list)):
                    ub_start = self.second_pass_archive.execution_order_of_every_ub_list[x][0]
                    block_id = self.second_pass_archive.get_ublock_id_from_address(ub_start)
                    corresponding_rows = self.second_pass_archive.execution_order_of_every_ub_list[x][1]
                    
                    f.write(f"{x}: UB addr = {ub_start} with ID: {block_id} yields: {self.second_pass_archive.get_ublock_from_address(ub_start).instructions}\n")
                f.write(str(len(self.second_pass_archive.instruction_blocks_dict)))
                f.write(str(len(self.second_pass_archive.hashed_blocks)))
        except Exception as e:
            print(e)
            print("ruhroh")
    
    def regroup(self):
        for addr in self.second_pass_archive.instruction_blocks_dict:
            b_id = self.second_pass_archive.get_ublock_id_from_address(addr)    # block id of addr
            last_line = self.second_pass_archive.get_ublock_from_address(addr).instructions[-1]

            last_line_info = self.trace_map.get_parsed_obj_of_line(last_line)

            if last_line_info is not None:
                last_line_operator = last_line_info.get_operator()
                line_operands = last_line_info.get_operands()
                
                if len(line_operands) == 1:
                    if last_line_operator == "jmp":
                        self.groups["jmp"].append(b_id)
                    elif last_line_operator != "call" and line_operands[0].data_type == OPERAND_TYPE.ADDRESS:
                        if line_operands[0].corresponding_data not in self.groups:
                            self.groups[line_operands[0].corresponding_data] = []
                        self.groups[line_operands[0].corresponding_data].append(b_id)

    def test_regroup(self):
        for x in self.groups:
            print(f"{x}: {self.groups[x]}\n")
            for ids in self.groups[x]:
                block_addr = self.second_pass_archive.get_ublock_address_from_id(ids)
                ublock = self.second_pass_archive.get_ublock_from_address(block_addr)
                print(f"{ublock.instructions}\n")

    def testoutput(self, filename):
        try:
            with open(filename, "w") as f:
                f.write(f"{filename}\n")

                f.write(f"Total unique blocks:              {len(self.second_pass_archive.instruction_blocks_dict)}\n")
                f.write(f"                                                                                                             \n")
                f.write(f"Total unique blocks (distinct):   {len(self.handlers)}\n                                                     \n")
                f.write(f"                                                                                                             \n")
                f.write(f"# of unique blocks executed:   {len(self.second_pass_archive.execution_order_of_every_ub_list)}              \n")
                f.write(f"-------------------------------------------------------------------------------------------------------------\n\n")
                f.write(f"# of x86-64 instructions including junk: {len(self.trace_map.every_executed_addr_data_list)}                 \n")
                f.write(f"initial block count:   {len(self.first_pass_archive.instruction_blocks_dict)}                                \n")
                f.write(f"# of initial blocks executed:   {len(self.first_pass_archive.execution_order_of_every_ub_list)}              \n")
                f.write(f"                                                                                                             \n")
                f.write(f"                                                                                                             \n")
                f.write(f"-------------------------------------------------------------------------------------------------------------\n\n")

                for blk in self.second_pass_archive.instruction_blocks_dict:
                    block_id = self.second_pass_archive.get_ublock_id_from_address(blk)
                    f.write(f"UB ID: {block_id} - {self.second_pass_archive.instruction_blocks_dict[blk].instructions}\n")

                for x in range(0, len(self.second_pass_archive.execution_order_of_every_ub_list)):
                    ub_start = self.second_pass_archive.execution_order_of_every_ub_list[x][0]
                    block_id = self.second_pass_archive.get_ublock_id_from_address(ub_start)
                    corresponding_rows = self.second_pass_archive.execution_order_of_every_ub_list[x][1]
                    
                    f.write(f"{x}: UB addr = {ub_start} with ID: {block_id} yields:\n")
                    for line in self.second_pass_archive.get_ublock_from_address(ub_start).instructions:
                        f.write(f"\t\t{line}\n")
                
                f.write(f"distinct # of ublocks: {len(self.handlers)}\n")
                for x in self.handlers:
                    full_line = ""
                    blockid = self.handlers[x][0]
                    addr = self.second_pass_archive.get_ublock_address_from_id(blockid)
                    ublock = self.second_pass_archive.get_ublock_from_address(addr)
                    f.write(f"block IDs [duplicates]: {self.handlers[x]}\n")
                    f.write(f"{ublock.instructions}\n\n")
                    f.write(f"bytes: ")
                    for opc in ublock.instructions:
                        parsed_data = self.trace_map.get_parsed_obj_of_line(opc)
                        if parsed_data is not None:
                            f.write(f"{opc}: {parsed_data.get_opcodes()}\n")
                            full_line += parsed_data.get_opcodes()
                    
                    f.write(f"\nbytecode len: {len(full_line)} -   {full_line}\n\n")

                        
                
        except Exception as e:
            print(e)
            print("ruhroh")

    def test(self):
        dup_dict = {}
        #self.first_pass_archive.output_stats()
        #self.second_pass_archive.print_blocks()
        
        #for block_hash in self.second_pass_archive.hashed_blocks:
        #    same_hash_blocks_list = self.second_pass_archive.hashed_blocks[block_hash]
        #    block_address = same_hash_blocks_list[0]     # get first element; the rest (if any) have exact same data so we deal with them later after we filter one 
        #    ublock = self.second_pass_archive.get_ublock_from_address(block_address)
        #    print(same_hash_blocks_list)
        
        self.clean_blocks()
        #self.testoutput("no_protections_packed_vmp15_getmodulehandle2_trace.txt") 
        self.regroup()
        self.test_regroup()
        #self.testoutput("vm_enter_out.txt")
        self.testoutput("no_protections_packed_vmp8_unpacking_trace.txt")
     
    
    def process_into_blocks(self, disasm_string, current_addr, regvals, memval, opcodes): 

        self.trace_map.log_all_executed_addr_data(current_addr, regvals, memval)    # EVERY RIP; including "duplicate" addrs
        self.trace_map.log_instr_of_all_unique_addrs(current_addr, disasm_string)   # only keep track of lines never seen. "simplify" next step

        self.trace_map.parse_unique_lines(disasm_string, opcodes)                   # map parsed lines in English disasm representation... (as opposed to bytes)? 

        if self.trace_map.at_end_of_trace() or re.search(REGEXPATTERNS.PATTERN_NOT_BB, disasm_string):  # end of a block? or last line?
            self.the_builder.set_new_block_state(True)
        else:
            self.the_builder.set_new_block_state(False)
        
        if self.the_builder.is_block_empty():                                       # empty block = start of 'new' block
            self.the_builder.mark_start_of_block(current_addr)
        
        self.the_builder.add_line_to_block(disasm_string)                           # 

        if self.the_builder.get_new_block_state():                                  # signal that end of block reached

            if not self.the_builder.is_block_empty():                               # confirm non-empty (handles situations with multiple consecutive jumps)

                ub_addr = self.the_builder.get_block_address()
                
                self.first_pass_archive.keep_track(ub_addr, self.trace_map.nth_line)
                
                if not self.first_pass_archive.is_encountered_block(ub_addr):
                    self.the_builder.hash_completed_block()

                    current_bid = self.first_pass_archive.get_id_count()
                    self.first_pass_archive.create_entries(self.the_builder.create_ub(current_bid), current_bid)

                    self.first_pass_archive.update_id_count()
                
                self.trace_map.nth_line.clear()

            self.the_builder.cleanup()
    
    def replace_jmps_and_reorder_blocks(self):
        index = 0
        self.the_builder.reset()    # clear from past usage

        current_execution_trail = []    # 
        encountered_path = {}
        ub_with_jmp_removed = []
        order_log = []
        end_of_block_reached = False
        hash_of_current_paths_taken = ""
        
        while index < len(self.first_pass_archive.execution_order_of_every_ub_list):
            current_addr = self.first_pass_archive.execution_order_of_every_ub_list[index][0]
            corresponding_executed_num = self.first_pass_archive.execution_order_of_every_ub_list[index][1]
            if index == 0:  # set state at start 
                self.the_builder.mark_start_of_block(current_addr)
            else:
                if self.the_builder.get_new_block_state():
                    self.the_builder.mark_start_of_block(current_addr)
                    self.the_builder.set_new_block_state(False) # reset 

            first_pass_block_id = self.first_pass_archive.get_ublock_id_from_address(current_addr)
            first_pass_current_ublock = self.first_pass_archive.get_ublock_from_address(current_addr)
            first_pass_block_lines = first_pass_current_ublock.get_disasm_lines().copy()
            last_line = first_pass_block_lines[-1]
            parsed_last_line = self.trace_map.every_disasm_parsed_dict[last_line]
            

            second_pass_block_id = self.second_pass_archive.get_id_count()

            
                #self.second_pass_archive.blocks_ID_dict[second_pass_block_id]
            
            if parsed_last_line == None:                        # non sse/avx? good to go
                current_execution_trail.append(current_addr)

                for remaining_lines in first_pass_block_lines:      # "save" all of block since we know it's not branch/cf related at all
                    ub_with_jmp_removed.append(remaining_lines)
            
            else:   # valid parsed data

                last_line_operator = parsed_last_line.get_operator()

                if last_line_operator == "jmp":                             
                    last_line_operand = parsed_last_line.operand_list[0]
                    current_execution_trail.append(current_addr)            # keep track of "path".

                    if last_line_operand.data_type == OPERAND_TYPE.ADDRESS:     # want to 'remove' unconditional jmps
                        
                        if len(first_pass_block_lines) > 1:
                            first_pass_block_lines.pop(-1)
                            corresponding_executed_num.pop(-1)              # get rid of row of  jmp instruction 

                            for remaining_lines in first_pass_block_lines:
                                ub_with_jmp_removed.append(remaining_lines)
                            
                            for num in corresponding_executed_num:
                                order_log.append(num)                       # rest of the rows good

                        end_of_block_reached = False
                    else:
                        end_of_block_reached = True
                        
                elif last_line_operator != "jmp" and \
                (last_line_operator == "call" or last_line_operator == "ret" or last_line_operator[0] ==  "j"):
                # first check it's not a JMP. then if we come across something that starts with j, we know it's jcc

                    current_execution_trail.append(self.first_pass_archive.get_ublock_address_from_id(first_pass_block_id))
                    end_of_block_reached = True
                
                else:

                    last_addr_executed_data = self.trace_map.get_entry_from_every_executed_addr_data(-1) # very last addr from full trace
                    last_addr_executed = last_addr_executed_data[0]
                    line_of_last_addr = self.trace_map.disasm_history_dict[last_addr_executed]

                    #if index == len(self.first_pass_archive.execution_order_of_every_ub_list) - 1:
                    #    if corresponding_executed_num[-1] == len(self.trace_map.every_executed_addr_data_list) - 1:
                    #        current_execution_trail.append(current_addr)
                    #        end_of_block_reached = True
                    if last_line == line_of_last_addr:
                        current_execution_trail.append(current_addr)
                        end_of_block_reached = True
                
                if end_of_block_reached:
                    for ub_addr in current_execution_trail: # hash consecutive addrs 
                        self.the_builder.hash_lines(ub_addr)
                    
                    
                    if self.the_builder.get_current_hash() not in encountered_path:   # have we come across this sequence before?
                        encountered_path[self.the_builder.get_current_hash()] = self.the_builder.get_block_address()
                        self.the_builder.reset_hash()

                        for lines in ub_with_jmp_removed:
                            self.the_builder.add_line_to_block(lines)
                        
                        for lines in first_pass_block_lines:
                            self.the_builder.add_line_to_block(lines)
                        
                        
                        
                        if second_pass_block_id not in self.second_pass_archive.blocks_ID_dict:
                            self.second_pass_archive.create_entries(self.the_builder.create_ub(second_pass_block_id), second_pass_block_id)
                        
                        self.second_pass_archive.update_id_count()

                    for num in corresponding_executed_num:
                        order_log.append(num)
                    
                    #f.write(f"disasm: {self.the_builder.bb_instr}\norder log: {order_log}\n\n")
                    self.second_pass_archive.keep_track(self.the_builder.get_block_address(), order_log.copy())
                    self.the_builder.reset()
                    self.the_builder.set_new_block_state(True)
                    ub_with_jmp_removed.clear()
                    current_execution_trail.clear()
                    order_log.clear()
            index += 1
    
    def replace_jmps_and_reorder_blocks_write_to_file(self):
        try:
            with open("order2test.txt", "w") as f:
                index = 0
                self.the_builder.reset()    # clear from past usage

                current_execution_trail = []    # 
                encountered_path = {}
                ub_with_jmp_removed = []
                order_log = []
                end_of_block_reached = False
                hash_of_current_paths_taken = ""
                
                while index < len(self.first_pass_archive.execution_order_of_every_ub_list):
                    current_addr = self.first_pass_archive.execution_order_of_every_ub_list[index][0]
                    corresponding_executed_num = self.first_pass_archive.execution_order_of_every_ub_list[index][1]
                    if index == 0:  # set state at start 
                        self.the_builder.mark_start_of_block(current_addr)
                    else:
                        if self.the_builder.get_new_block_state():
                            self.the_builder.mark_start_of_block(current_addr)
                            self.the_builder.set_new_block_state(False) # reset 

                    first_pass_block_id = self.first_pass_archive.get_ublock_id_from_address(current_addr)
                    first_pass_current_ublock = self.first_pass_archive.get_ublock_from_address(current_addr)
                    first_pass_block_lines = first_pass_current_ublock.get_disasm_lines().copy()
                    last_line = first_pass_block_lines[-1]
                    parsed_last_line = self.trace_map.every_disasm_parsed_dict[last_line]
                    

                    second_pass_block_id = self.second_pass_archive.get_id_count()

                    
                        #self.second_pass_archive.blocks_ID_dict[second_pass_block_id]
                    
                    if parsed_last_line == None:
                        current_execution_trail.append(current_addr)

                        for remaining_lines in first_pass_block_lines:
                            ub_with_jmp_removed.append(remaining_lines)
                    
                    else:   # valid parsed data

                        last_line_operator = parsed_last_line.get_operator()

                        if last_line_operator == "jmp":
                            last_line_operand = parsed_last_line.operand_list[0]
                            current_execution_trail.append(current_addr)

                            if last_line_operand.data_type == OPERAND_TYPE.ADDRESS:
                                
                                if len(first_pass_block_lines) > 1:
                                    first_pass_block_lines.pop(-1)
                                    corresponding_executed_num.pop(-1)

                                    for remaining_lines in first_pass_block_lines:
                                        ub_with_jmp_removed.append(remaining_lines)
                                    
                                    for num in corresponding_executed_num:
                                        order_log.append(num)

                                end_of_block_reached = False
                            else:
                                end_of_block_reached = True
                        elif last_line_operator != "jmp" and \
                        (last_line_operator == "call" or last_line_operator == "ret" or last_line_operator[0] ==  "j"):
                        # first check it's not a JMP. then if we come across something that starts with j, we know it's jcc

                            current_execution_trail.append(self.first_pass_archive.get_ublock_address_from_id(first_pass_block_id))
                            end_of_block_reached = True
                        
                        else:

                            last_addr_executed_data = self.trace_map.get_entry_from_every_executed_addr_data(-1) # very last addr from full trace
                            last_addr_executed = last_addr_executed_data[0]
                            line_of_last_addr = self.trace_map.disasm_history_dict[last_addr_executed]

                            if index == len(self.first_pass_archive.execution_order_of_every_ub_list) - 1:
                                if corresponding_executed_num[-1] == len(self.trace_map.every_executed_addr_data_list) - 1:
                                    current_execution_trail.append(current_addr)
                                    end_of_block_reached = True
                            elif last_line == line_of_last_addr:
                                current_execution_trail.append(current_addr)
                                end_of_block_reached = True
                        
                        if end_of_block_reached:
                            for ub_addr in current_execution_trail: # hash consecutive addrs 
                                self.the_builder.hash_lines(ub_addr)
                            
                            
                            if self.the_builder.get_current_hash() not in encountered_path:   # have we come across this sequence before?
                                encountered_path[self.the_builder.get_current_hash()] = self.the_builder.get_block_address()
                                self.the_builder.reset_hash()

                                for lines in ub_with_jmp_removed:
                                    self.the_builder.add_line_to_block(lines)
                                
                                for lines in first_pass_block_lines:
                                    self.the_builder.add_line_to_block(lines)
                                
                                
                                
                                if second_pass_block_id not in self.second_pass_archive.blocks_ID_dict:
                                    self.second_pass_archive.create_entries(self.the_builder.create_ub(second_pass_block_id), second_pass_block_id)
                                
                                self.second_pass_archive.update_id_count()

                            for num in corresponding_executed_num:
                                order_log.append(num)
                            
                            f.write(f"disasm: {self.the_builder.bb_instr}\norder log: {order_log}\n\n")
                            self.second_pass_archive.keep_track(self.the_builder.get_block_address(), order_log.copy())
                            self.the_builder.reset()
                            self.the_builder.set_new_block_state(True)
                            ub_with_jmp_removed.clear()
                            current_execution_trail.clear()
                            order_log.clear()
                    index += 1
            

        except Exception as e:
            print(f"error: {e} {type(e)}")

    def test_if_hashes_blocks_different(self):
        b_filter = {}
        for unique_block_addr in self.first_pass_archive.instruction_blocks_dict:
            block_hash = self.first_pass_archive.get_hash_from_address(unique_block_addr)
            same_hash_blocks_list = self.first_pass_archive.hashed_blocks[block_hash]
            if block_hash not in b_filter:
                b_filter[block_hash] = []
            b_filter[block_hash].append(unique_block_addr)
        
        for x in b_filter:
            addr_list = b_filter[x]
            for addr in addr_list:
                print(f"addrs with same hash: {addr}")
                if addr in self.first_pass_archive.blocks_ID_dict:
                    print(f"addr mapped to block ID: {self.first_pass_archive.blocks_ID_dict[addr]} instr: {self.first_pass_archive.instruction_blocks_dict[addr].instructions}")
    
    def clean_blocks(self):
        keep_these = {}

        fixed_list = []

        for block_hash in self.second_pass_archive.hashed_blocks:
            same_hash_blocks_list = self.second_pass_archive.hashed_blocks[block_hash]
            block_address = same_hash_blocks_list[0]     # get first element; the rest (if any) have exact same data so we deal with them later after we filter one 
            ublock = self.second_pass_archive.get_ublock_from_address(block_address)

            
            
            
            block_lines = ublock.get_disasm_lines()
            

            curr_index = 0

            while curr_index < len(block_lines):
                current_instruction = block_lines[curr_index]

                parsed_line_data = self.trace_map.get_parsed_obj_of_line(current_instruction)

                if parsed_line_data is not None:    # filter out not covered stuff

                    

                    current_line_operator = parsed_line_data.get_operator()
                    curr_operands = parsed_line_data.get_operands()

                    if curr_index == (len(block_lines) - 1):
                        if current_line_operator in self.branches:
                            self.branches[current_line_operator] += 1
                        else:
                            if current_line_operator not in self.missed:
                                self.missed[current_line_operator] = 0
                        
                        if len(curr_operands) > 0:
                            if curr_operands[0].corresponding_data not in self.destinations:
                                self.destinations[curr_operands[0].corresponding_data] = ""
                            self.destinations[curr_operands[0].corresponding_data] += current_line_operator

                    
        

                    self.the_cleaner.process_lines(current_line_operator, curr_operands, curr_index)

                     
                else:
                    self.the_cleaner.add_current_line(X64REGS.SPECIAL, curr_index)
                
                
                curr_index += 1
            '''
            keep_these = self.the_cleaner.return_lines_to_keep()
            #print(keep_these)
            fixed_list = sorted(keep_these, reverse=True)
            #print(fixed_list)
            last = len(block_lines) - 1
            adjust = 0
            while last >= 0:
                if last not in fixed_list:
                    block_lines.pop(last)
                last -= 1
            
            keep_these.clear()
            self.the_cleaner.reset()
            fixed_list.clear()
            print(block_lines)
            '''
            new_hash = ""
            print(f"PRE-CLEANED block lines:\n")
            for ln in block_lines:
                print(f"\t{ln}")
            print(f"\n\n\t\t# of lines: {len(block_lines)}\n")
            keep_these = self.the_cleaner.return_lines_to_keep()
            #print(keep_these)
            if len(keep_these) == len(block_lines):
                print(f"No dead code in current block.")
            else:
                print(f"=============\n")
                for x in range(0, len(block_lines)):
                    if x in keep_these:
                        print(f"{x} {block_lines[x]}\n")
                    else:
                        print(f"{x}\t\t\t\t\t\t\t\t\t{block_lines[x]}\n")
                print(f"=============\n")
                
                fixed_list = sorted(keep_these, reverse=True)
                #print(fixed_list)

                last = len(block_lines) - 1
                while last >= 0:
                    if last not in fixed_list:
                        block_lines.pop(last)
                    last -= 1

                #print(f"post-cleaned block lines:\n{block_lines}\n\n\t# of lines: {len(block_lines)}\n")
                #for x in range(0, len(block_lines)):
                #    print(f"{block_lines[x]}")
                print(f"POST-CLEANED block lines:\n")
                for ln in block_lines:
                    print(f"\t{ln}")
                    new_hash += self.the_builder.md5_hash(ln)
                ublock.hash_of_block = new_hash
                print(f"\n\n\t\t# of lines: {len(block_lines)}\n")


            if len(same_hash_blocks_list) > 1:
                for blockaddr in same_hash_blocks_list:
                    if blockaddr != block_address:
                        self.second_pass_archive.instruction_blocks_dict[blockaddr].instructions =block_lines.copy()
                        self.second_pass_archive.instruction_blocks_dict[blockaddr].hash_of_block = ublock.hash_of_block
                    if self.second_pass_archive.instruction_blocks_dict[blockaddr].hash_of_block not in self.handlers:
                        self.handlers[self.second_pass_archive.instruction_blocks_dict[blockaddr].hash_of_block] = []
                    self.handlers[self.second_pass_archive.instruction_blocks_dict[blockaddr].hash_of_block].append(self.second_pass_archive.get_ublock_id_from_address(blockaddr))
            
            
            if ublock.hash_of_block not in self.handlers:
                self.handlers[ublock.hash_of_block] = []
            self.handlers[ublock.hash_of_block].append(ublock.get_ID())

            
            print("-------------------------------------------------------------------------\n")
            keep_these.clear()
            self.the_cleaner.reset()

     
       



class PluginPrintExecCounts(IPlugin):

    def execute(self, api: Api):

        trace = api.get_visible_trace()
        if not trace:
            return

        api.print('')

        trace_data = api.get_trace_data()
        ip_name = trace_data.get_instruction_pointer_name()
        if ip_name not in trace_data.regs:
            api.print('Error. Unknown instruction pointer name.')
            return
        ip_index = trace_data.regs[ip_name]

        trace_len = len(trace)
        vmp = cVMP_Regex(trace_len)

        rangefilter = True
        
        #vmp15 start addr: 0x7ff629e40000
        #no_protections_packed_vmp1_unpacking_addr_range  0x7ff7c99e1000_to_0x7ff7c9b67000

        # no_protections_packed_2 0x7ff6485b0000_to_0x7ff64872f000

        #no_protections_packed_3 0x7ff6feb81000_to_0x7ff6fed08000

        #no_protections_packed_4 0x7ff64ff20000_to_0x7ff6500af000

        #no_protections_packed_5 0x7ff7d1030000_to_0x7ff7d11ba000

        #no_protections_packed_6 0x7ff7a9c20000_to_0x7ff7a9da6000

        # 8 0x7ff618f60000 to 0x7ff6190e4000
        #no_protections_packed_8_0x7ff618f60000_to_0x7ff6190e4000

        # vmp hwid license unpack me range:
        # START: 7ff641e40000
        # END: 7ff643c35000

        # vmp devirtme range:
        # START: 140000000
        # end:   1401E2000

        START_ADDRESS = 0x7ff7c99e1000 
        END_ADDRESS = 0x7ff7c9b67000
        for t in trace:
            #addr = hex(t['regs'][ip_index])[2:]
            val = None

            addr = t['regs'][ip_index]
           
            register_values = t['regs']
            memory_value = t['mem']
            op_codes = t['opcodes']
            
            if len(memory_value) > 0:
                val = hex(memory_value[0]['value'])
            
            
            # project6.vmp.exe addr range: 0x7ff792750000 - 0x7ff7928e3000
            if rangefilter:
                vmp.filter_addr_range(START_ADDRESS, END_ADDRESS, t['disasm'], addr, register_values, val, op_codes)
            else:
                vmp.process_into_blocks(t['disasm'], hex(addr)[2:], register_values, val, op_codes)
            #vmp.filter_addr_range(0x140000000,0x1401E2000, t['disasm'], addr, register_values, val, op_codes)

            #vmp.process_into_blocks(t['disasm'], hex(addr)[2:], register_values, val, op_codes)
        
        vmp.replace_jmps_and_reorder_blocks()

        vmp.test()
        print("done")
        return 
         
