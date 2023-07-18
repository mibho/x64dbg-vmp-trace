import re


from .fx64_operands import *

class sse_regs:
    XMM0 = 'xmm0'
    XMM1 = 'xmm1'
    XMM2 = 'xmm2'
    XMM3 = 'xmm3'
    XMM4 = 'xmm4'
    XMM5 = 'xmm5'
    XMM6 = 'xmm6'
    XMM7 = 'xmm7'
 
 


class MATCH:
    REG_SIZE     = 2
    SEGMENT_TYPE = 7
    MEM_DISP     = 9



class disasm_parsed:
    
    def __init__(self):
        self.operator = ""

        self.operand_list = []  # list of operand objects 
        self.operand_count = 0
        self.opcodes = ""
    
    def set_opcodes(self, opc_bytes):
        self.opcodes = opc_bytes
    
    def get_opcodes(self):
        return self.opcodes

    def set_operator(self, operator):
        self.operator = operator
    
    def get_operator(self):
        return self.operator

    def get_operand_count(self):
        return self.operand_count
    
    def get_operands(self):
        return self.operand_list
    
    def has_operands(self):
        return self.operand_count != 0
    
    def add_operand(self):
        self.operand_list.append(operand())
        self.operand_count += 1
    
    def get_curr_operand_obj(self):

        if self.operand_count >= 1:
            
            curr_pos = self.operand_count - 1

            return self.operand_list[curr_pos]
        
        return
    
    def reset(self):
        self.operator = ""
        self.operand_list.clear()
        self.operand_count = 0
    
    def output(self):
        print(f"operator: {self.operator}")
        print(f"op_count: {self.operand_count}")
        if self.operand_count != 0:
            print(f"operands not empty. printing")
            print("START OF OPERANDS LIST\n---------------------------")
            for x in self.operand_list:
                x.output()
            print("END -----------------------------------------")
        #self.get_curr_operand_obj().output()

    




class efParserClass:

    def __init__(self):
        self.instruction_line = disasm_parsed()
        self.potential_operands = []
        self.line_split_by_spaces = []
        self.count = 0
    
    def copy(self):

        return (self.instruction_line.operator, self.instruction_line.operand_count, self.instruction_line.operand_list.copy())
    
    def complete_parse(self, instr_string):
        self.parse_line(instr_string)
        #return self.instruction_line


    def reset(self):
        self.instruction_line.reset()
        self.potential_operands.clear()
        self.line_split_by_spaces.clear()

    def prep_line(self, disasm_line):
        self.potential_operands = self.split_on_token(",", disasm_line)

        for line in self.potential_operands:
            words = self.split_on_token(" ", line)
            for word in words:
                self.line_split_by_spaces.append(word)

    def parse_line(self, disasm_line):

        self.prep_line(disasm_line)     
                                    # remove 1st word from line. guaranteed to be operator
        self.count += 1

        self.determine_operands() 
        #if self.x > 0:
            #self.instruction_line.output()
           # exit()

    def is_not_empty(self):
        if len(self.potential_operands) >= 1:
            if len(self.potential_operands[0]) > 0:
                return True
            
        return False
    
    def has_words(self):
        remaining_words = len(self.line_split_by_spaces)
        return remaining_words != 0

    def number_of_operands(self):

            num_commas = len(self.potential_operands)   

            if num_commas == 1:    # string split() ret 1 even if not found.
                char_count = len(self.potential_operands[0])

                if char_count > 0: 
                    return 1
                else:
                    return 0
            else:
                return num_commas

    def determine_operands(self):
        """
        what should this do? 
            with the remaining data in potential_operands and line_split_by_spaces, 
            need to check: 
            line is split by # of commas.               rep movsb byte ptr [rdi], byte ptr [rsi]

            case 1: no comma present

                a. rdtsc                        [1 word instruction with 0 operands]
                b. pop r12                      [1 word instruction with 1 operand specified]
                c. push qword ptr [rbp]         [1 word instruction with 1 operand, with size explicitly specified]
            
            case 2: 1 comma present

                a. mov r8d, eax
                b. mov eax, 0x800              

            plan:
                split up entire sentence by commas.
                    0 commas? then we're dealing with the whole instruction provided

                    1 comma? then 1st part has operator operand and the 2nd just the operand. 
                    go thru each sequentially  
        """
        if self.is_not_empty():
            operator_set = False
            new_operand = False
            tagged = False
            self.x = 0
              # push r12 = returns 1. rdtsc = returns 1. mov r12, rax = returns 2
            for line in self.potential_operands:

                words = self.split_on_token(" ", line)
                new_operand = True
                go_next = False
                while len(words) != 0 and go_next == False: # popping 
                    
                    word = words.pop(0)


                    if not operator_set:                            # run once
                        if word[0] == "b":          # cheeky workaround for rep string ops 
                            if len(words) == 1:
                                if word[1] == "n" and word[2] == "d":
                                    word += " " + words.pop(0)
                        elif word[0] == "r":
                            if len(word) == 3:  # rep
                                if word[2] == "p":
                                    word += " " + words.pop(0)
                                    print(words)
                                    
                                    self.x += 1
                                    tagged = True
                                    
                        self.instruction_line.set_operator(word)
                        operator_set = True
                    else:
                        if new_operand:
                            self.instruction_line.add_operand()
                            new_operand = False

                        curr_operand = self.instruction_line.get_curr_operand_obj()
                        operand_involves_mem = self.parse_mem_access(line)

                        

                        if operand_involves_mem is not None: # mem acc detected

                            if operand_involves_mem[0] is not None: # brackets
                                potential_offsets = self.split_on_token(" ", operand_involves_mem[0])
                                tempsign = "+"

                                for val in potential_offsets:
                                    
                                    if val != '+' and val != '-':
                                        result = self.parse_reg(val)
                                        if not curr_operand.is_operand_set():
                                            curr_operand.set_operand_type(result[0])
                                            curr_operand.set_specified_size(result[1])
                                            curr_operand.set_data(result[2])
                                            curr_operand.operand_val_set()
                                        else:
                                            #print(f"{result[0]} | {result[1]} | {result[2]} | {result[3]} | {tempsign}")
                                            curr_operand.add_offset(result[0],result[2], result[3], tempsign)
                                            tempsign = "+"
                                    else:
                                        if val == "-":
                                            tempsign = "-"
                                        

                            if operand_involves_mem[1] is not None: # reg size
                                reg_sz = operand_involves_mem[1]
                                if reg_sz[0] == 'q' and reg_sz[1] == 'w':
                                    curr_operand.set_specified_size(REG_SIZE.QWORD)
                                elif reg_sz[0] == 'd' and reg_sz[1] == 'w':
                                    curr_operand.set_specified_size(REG_SIZE.DWORD)                           
                                elif reg_sz[0] == 'w' and reg_sz[1] == 'o':
                                    curr_operand.set_specified_size(REG_SIZE.WORD)
                                elif reg_sz[0] == 'b' and reg_sz[1] == 'y':
                                    curr_operand.set_specified_size(REG_SIZE.BYTE)

                            if operand_involves_mem[2] is not None: # segment 
                                start = operand_involves_mem[2][0]
                                if start == 'c': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.CS)
                                elif start == 'd': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.DS)
                                elif start == 'e': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.ES)
                                elif start == 'f': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.FS)
                                elif start == 'g': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.GS)
                                elif start == 's': curr_operand.set_mem_ref(True, True, SEGMENT_TYPE.SS)
                            else:
                                curr_operand.set_mem_ref(True)
                            go_next = True
                        
                            if tagged: 
                                print(f"{curr_operand.get_data()}")
                                if self.x == 2: exit()
                                tagged = False


                            
                        else:
                            curr_operand.set_mem_ref(False)
                            result = self.parse_reg(word)
                            curr_operand.set_operand_type(result[0])
                            curr_operand.set_specified_size(result[1])
                            curr_operand.set_data(result[2])
                            curr_operand.operand_val_set()


    def split_on_token(self, token, disasm_line):
        """
        ----------------
        RETURN: a LIST consisting of disasm_line broken up into <n + 1> strings 
                if <n> matches of token are detected  
        ----------------
        param1: token   
            TYPE: char [str]
                    - a character to separate the given line by.
        
        param2: disasm_line
            TYPE: str
                    - disassembly string of an x86/x86-64 instruction
        """
        if disasm_line is not None:
            separated_line = disasm_line.split(token)

            separated_line = [word for word in separated_line if word]  # filter out empty dummy words

            return separated_line
        
        return None # u broke this

    def parse_mem_access(self, disasm_line):
        found = re.search(r'((((d|q)?wo)|by)(\w|\s)+)?(((c|d|e|f|g|s)s):)?(\[.*(\+|\-)?\])', disasm_line)#re.search(r'(((d|q)?wo)|by)(\w|\s)+(((c|d|e|f|g|s)s):)?(\[.*(\+|\-)?\])', disasm_line) # ((c|d|e|f|g|s)s):(\[.*(\+|\-)?\])
        if found:      
            brackets_found = found.group(MATCH.MEM_DISP)[1:-1]      
            size_found = found.group(MATCH.REG_SIZE)
            segment_found = found.group(MATCH.SEGMENT_TYPE)
            
            return (brackets_found, size_found, segment_found)
        
        return None

    def parse_reg(self, disasm_line):
        #print(f"orig line: {disasm_line}")
        reg_sz = 0
        corresponding_reg = ""
        offset_coeff = re.search(r'(\*)', disasm_line)
        offset_coeff2 = re.search(r'(\*\d)', disasm_line)
                    #current 'formula' doesnt stop after 12 hex characters detected... need fix 
        detected_coeff = None
        imm_found = re.search(r'(((-?)0x.+)|(^(-?)\d+$))|(([0-9]|[a-fA-F]){12})', disasm_line) # ([0-9]|[a-fA-F]){12}|-?(0x.+)|(^\d+$) <- prev pattern BUT doesnt capture negative #s

        if imm_found:

            return (OPERAND_TYPE.CONSTANT, REG_SIZE.IGNORE, imm_found.group(0), None)
        else:
                # otherwise if it's not an address or constant, it's gotta be a register since memory is dealt with
            if offset_coeff:
                #c_index = offset_coeff.span(0)[1]
                c_index = offset_coeff.span(0)[0]
                detected_coeff = disasm_line[(c_index + 1):]
                disasm_line = disasm_line[0:c_index] # remove coefficient so have just reg
                

            word_len = len(disasm_line)

            if word_len == 2:
                if disasm_line[0] == 'r':
                    reg_sz = REG_SIZE.QWORD
                    if disasm_line[1] == '8':
                        corresponding_reg = REG_TYPE.R8
                    elif disasm_line[1] == '9':
                        corresponding_reg = REG_TYPE.R9
                else:
                    if disasm_line[0] == 'a':               # other variants of registers dont start w/ "a"
                        corresponding_reg = REG_TYPE.RAX
                    elif disasm_line[0] == 'c':             # ^
                        corresponding_reg = REG_TYPE.RCX
                    else:
                        if disasm_line[0] == 'b':           # RBP and RBX both have 2 letter regs w/ 'b'
                            if disasm_line[1] == 'p':
                                corresponding_reg = REG_TYPE.RBP
                            else:
                                corresponding_reg = REG_TYPE.RBX
                        elif disasm_line[0] == 'd':
                            if disasm_line[1] == 'i':
                                corresponding_reg = REG_TYPE.RDI
                            else:
                                corresponding_reg = REG_TYPE.RDX    
                        elif disasm_line[0] == 's':
                            if disasm_line[1] == 'i':
                                corresponding_reg = REG_TYPE.RSI
                            else:
                                corresponding_reg = REG_TYPE.RSP

                    if disasm_line[1] == 'x' or disasm_line[1] == 'p' or disasm_line[1] == 'i':
                        reg_sz = REG_SIZE.WORD
                    elif disasm_line[1] == 'h':
                        reg_sz = REG_SIZE.HIBYTE
                    elif disasm_line[1] == 'l':
                        reg_sz = REG_SIZE.LOBYTE
                    else:
                        print(f"something big wrong 1. disasm line: {disasm_line} crash at trace line {self.count}")
                        return
            elif word_len == 3:
                    if disasm_line[0] == 'r' or disasm_line[0] == 'e':
                        if disasm_line[1] == '8' or disasm_line[1] == '9':
                            if disasm_line[1] == '8':
                                corresponding_reg = REG_TYPE.R8
                            elif disasm_line[1] == '9':
                                corresponding_reg = REG_TYPE.R9
                            
                            if disasm_line[2] == 'b':
                                reg_sz = REG_SIZE.BYTE
                            elif disasm_line[2] == 'w':
                                reg_sz = REG_SIZE.WORD
                            elif disasm_line[2] == 'd':
                                reg_sz = REG_SIZE.DWORD
                            else:
                                print(f"something big wrong 2. disasm line: {disasm_line} crash at trace line {self.count}")
                                return
                        else:

                            reg_sz = REG_SIZE.QWORD

                            if disasm_line[0] == 'e':
                                reg_sz = REG_SIZE.DWORD

                            if disasm_line[2] == '0' or disasm_line[2] == '1' or disasm_line[2] == '2' or disasm_line[2] == '3' or disasm_line[2] == '4' or disasm_line[2] == '5':
                                

                                if disasm_line[2] == '0':
                                    corresponding_reg = REG_TYPE.R10
                                elif disasm_line[2] == '1':
                                    corresponding_reg = REG_TYPE.R11
                                elif disasm_line[2] == '2':
                                    corresponding_reg = REG_TYPE.R12
                                elif disasm_line[2] == '3':
                                    corresponding_reg = REG_TYPE.R13   
                                elif disasm_line[2] == '4':
                                    corresponding_reg = REG_TYPE.R14
                                elif disasm_line[2] == '5':
                                    corresponding_reg = REG_TYPE.R15 
                            else:

                                if disasm_line[1] == 'a':
                                    corresponding_reg = REG_TYPE.RAX
                                elif disasm_line[1] == 'c':
                                    corresponding_reg = REG_TYPE.RCX
                                else:
                                    if disasm_line[1] == 'b':
                                        if disasm_line[2] == 'p':
                                            corresponding_reg = REG_TYPE.RBP
                                        elif disasm_line[2] == 'x':
                                            corresponding_reg = REG_TYPE.RBX
                                    elif disasm_line[1] == 'd':
                                        if disasm_line[2] == 'x':
                                            corresponding_reg = REG_TYPE.RDX
                                        elif disasm_line[2] == 'i':
                                            corresponding_reg = REG_TYPE.RDI
                                    elif disasm_line[1] == 's':
                                        if disasm_line[2] == 'i':
                                            corresponding_reg = REG_TYPE.RSI
                                        elif disasm_line[2] == 'p':
                                            corresponding_reg = REG_TYPE.RSP

                                    elif disasm_line[1] == 'i' and disasm_line[2] == 'p':
                                        corresponding_reg = REG_TYPE.RIP
                                    else:
                                        print(f"something big wrong 3. disasm line: {disasm_line} crash at trace line {self.count}")
                                        print(f"{self.line_split_by_spaces} {self.potential_operands}")
                                        return
                    else:

                        reg_sz = REG_SIZE.BYTE
                        if disasm_line[0] == 'b':
                            corresponding_reg = REG_TYPE.RBP
                        elif disasm_line[0] == 'd':
                            corresponding_reg = REG_TYPE.RDI
                        elif disasm_line[0] == 's':

                            if disasm_line[1] == 'i':
                                corresponding_reg = REG_TYPE.RSI
                            elif disasm_line[1] == 'p':
                                corresponding_reg = REG_TYPE.RSP
                        
                        
            
            elif word_len == 4:

                if disasm_line[2] == '0':
                    corresponding_reg = REG_TYPE.R10
                elif disasm_line[2] == '1':
                    corresponding_reg = REG_TYPE.R11
                elif disasm_line[2] == '2':
                    corresponding_reg = REG_TYPE.R12
                elif disasm_line[2] == '3':
                    corresponding_reg = REG_TYPE.R13   
                elif disasm_line[2] == '4':
                    corresponding_reg = REG_TYPE.R14
                elif disasm_line[2] == '5':
                    corresponding_reg = REG_TYPE.R15  
                
                if disasm_line[3] == 'b':
                    reg_sz = REG_SIZE.BYTE
                elif disasm_line[3] == 'w':
                    reg_sz = REG_SIZE.WORD
                elif disasm_line[3] == 'd':
                    reg_sz = REG_SIZE.DWORD
                else:
                    print(f"something big wrong 4. disasm line: {disasm_line} crash at trace line {self.count}")
                    return
            else:
                print(f"something big wrong 5. disasm line: {disasm_line} crash at trace line {self.count}")
                return
            
            
        #print(f"reg size: {reg_sz} corresponding reg: {corresponding_reg}")
        return (OPERAND_TYPE.REGISTER, reg_sz, corresponding_reg, detected_coeff)
 