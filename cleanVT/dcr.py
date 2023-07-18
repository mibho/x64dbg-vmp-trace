DEBUG_MSGS = False

from . import dcr_tools as dcrtools

from .fx64_operators import x86_ops

from .fx64_operands import *

REG_STATE = dcrtools.STATE

class instruction_chain:
    def __init__(self):
        self.sequence = {}
    
    def reset(self):
        self.sequence.clear()
    
    def size(self):
        return len(self.sequence)

    def add_link(self, line_num):
        if line_num not in self.sequence:
            self.sequence[line_num] = 0
    
    def transfer_to(self, ic_dst):
        
        if len(self.sequence) > 0:
            for line_num in self.sequence:
                ic_dst.add_link(line_num)

        else:
            if DEBUG_MSGS: print(f"current ic is empty.")
    
    def return_copy(self):
        return self.sequence.copy()

    def replace_with(self, replacement):
        self.sequence = replacement.return_copy()
    

class register_data:
    def __init__(self):
        self.last_state = REG_STATE.NOTSET
        self.live_lines = instruction_chain()



    
    def reset(self):
        self.last_state = REG_STATE.NOTSET
 

        self.live_lines.reset()
 

class dead_code_remover:

    def __init__(self):
        self.registers = {}
        self.init_regs()
        self.x64_operator = x86_ops()
        self.unknown = {}
    
    def reset(self):
        for reg in self.registers:
            self.registers[reg].reset()

    def init_regs(self):
        self.registers[X64REGS.RAX] = register_data()
        self.registers[X64REGS.RBX] = register_data()
        self.registers[X64REGS.RCX] = register_data()
        self.registers[X64REGS.RDX] = register_data()
        self.registers[X64REGS.RDI] = register_data()
        self.registers[X64REGS.RSI] = register_data()
        self.registers[X64REGS.RIP] = register_data()
        self.registers[X64REGS.RSP] = register_data()
        self.registers[X64REGS.RBP] = register_data()
        self.registers[X64REGS.R8]  = register_data()
        self.registers[X64REGS.R9]  = register_data()
        self.registers[X64REGS.R10] = register_data()
        self.registers[X64REGS.R11] = register_data()
        self.registers[X64REGS.R12] = register_data()
        self.registers[X64REGS.R13] = register_data()
        self.registers[X64REGS.R14] = register_data()
        self.registers[X64REGS.R15] = register_data()
        self.registers[X64REGS.FLAGS]= register_data()
        self.registers[X64REGS.SPECIAL]= register_data()
        self.registers[X64REGS.MEMORY]= register_data()
    

        # 
    def get_operator_info(self, string_of_operator):

        self.x64_operator.id_op(string_of_operator)
    
    def get_expected_effect(self, data_size, explicit_effect):

        return dcrtools.get_resulting_state(data_size, explicit_effect)

    def return_lines_to_keep(self):
        keep_these1 = {}

        for reg in self.registers:
            if self.registers[reg].live_lines.size() > 0:
                for lines1 in self.registers[reg].live_lines.sequence:
                    if lines1 not in keep_these1:
                        keep_these1[lines1] = 0
                        
        

        return keep_these1
        
    
    def process_lines(self, line_operator, operand_list, line_num):

        

        self.get_operator_info(line_operator)   # match w/ operator w/ regex and "evaluate" based on properties lol

        for a in self.x64_operator.unk_operators:       # filter for ones not included eg: lock, lfence
            if a not in self.unknown:
                self.unknown[a] = 0

        op_count = len(operand_list)

        if self.x64_operator.involves_stack:                # push, pop, pushfq, popfq, ret, call 

            self.add_current_line(X64REGS.RSP, line_num)

            if op_count == 0:   # pushfq, popfq, ret 

                if line_operator == "pushfq":   # push/save flags onto stack... flags data "preserved" on stack
                    self.add_prior_lines_to_from(X64REGS.RSP, X64REGS.FLAGS)
                
                elif line_operator == "popfq":  # value from stack popped into flags. flags data irrelevant
                    self.add_prior_lines_to_from(X64REGS.FLAGS, X64REGS.RSP)
                
                elif line_operator == "ret":    # end of block so dw. maybe relevant for ret <x> ? later 
                    x = 0
                
            elif op_count == 1: # push <data>, pop <data>, call <data>, ret <x> too...?

                target_operand = operand_list[0]

                if line_operator == "push": # only need consider case when operand == register

                    if target_operand.data_type == OPERAND_TYPE.REGISTER:

                        if target_operand.mem_accessed and target_operand.offset_count > 0: # eg: push qword ptr [r11 + r10]
            
                            for offset_data in target_operand.offset_list:

                                if offset_data[1] in self.registers:    # index 0 = OPERAND_TYPE, 1 = VALUE, 2 = COEFFICIENT, 3 = SIGN
                                    self.add_prior_lines_to_from(X64REGS.RSP, offset_data[1])


                        self.add_prior_lines_to_from(X64REGS.RSP, target_operand.corresponding_data)

                elif line_operator == "pop":

                    if target_operand.data_type == OPERAND_TYPE.REGISTER:

                        if target_operand.corresponding_data != X64REGS.RSP:

                            if target_operand.mem_accessed:
                               if target_operand.offset_count > 0:
                                for s_offset in target_operand.offset_list:
                                    dst_off = s_offset[1]
                                    if dst_off in self.registers: 
                                        self.save_prior_to_memory(dst_off) 
                            else:                               # pop <reg>. val taken from top of stack so reg data irrelevant. 
                                self.overwrite_move_transfer(target_operand.corresponding_data, X64REGS.RSP)
                
                elif line_operator == "call":

                    if target_operand.data_type == OPERAND_TYPE.REGISTER:
                        self.add_prior_lines_to_from(X64REGS.RSP, target_operand.corresponding_data)    # include any changes made to dst operand

        if self.x64_operator.rflags.requires_flag_val and not self.x64_operator.involves_stack: # lazy way to filter out pushfq. control flow related stuff

            if line_operator[0] == "j": # jcc 
                self.add_prior_lines_to_from(X64REGS.SPECIAL, X64REGS.FLAGS)    # save flags; required to evaluate ye or no
                self.add_current_line(X64REGS.SPECIAL, line_num)                # include the potential control flow 
            else:   #every other except jcc; set cmov 
    
                if op_count == 1 or op_count == 2:
                    target_operand = operand_list[0]

                    if op_count == 2:
                        src_operand = operand_list[1]

                        if src_operand.data_type == OPERAND_TYPE.REGISTER:
                            self.add_prior_lines_to_from(target_operand.corresponding_data, src_operand.corresponding_data)

                            if (src_operand.mem_accessed and target_operand.mem_accessed) or \
                                (src_operand.mem_accessed and not target_operand.mem_accessed) or \
                                 (not src_operand.mem_accessed and target_operand.mem_accessed):
                                self.add_prior_lines_to_from(X64REGS.MEMORY, src_operand.corresponding_data)
                                self.add_prior_lines_to_from(X64REGS.MEMORY, target_operand.corresponding_data)
                                self.add_current_line(X64REGS.SPECIAL, line_num)
                            
                                
                    
                        
                    self.add_prior_lines_to_from(target_operand.corresponding_data, X64REGS.FLAGS)  # requires flag vals
                    self.add_current_line(target_operand.corresponding_data, line_num)

        
        if self.x64_operator.rflags.flags_affected:

            if self.x64_operator.only_modifies_flags:

                last_state = self.get_last_state_of(X64REGS.FLAGS)  # budget way to evaluate if flag change has any effect

                if line_operator == "std" or line_operator == "cld":

                    if last_state != FLAG.DF_OVERWRITTEN:
                        self.set_last_state_of(X64REGS.FLAGS, FLAG.DF_OVERWRITTEN)
                        self.add_current_line(X64REGS.FLAGS, line_num)

                    x = 0 # update flag. DF_OVERWRITTEN
                elif line_operator == "stc" or line_operator == "clc": 
                    
                    if last_state != FLAG.CF_OVERWRITTEN:
                        self.set_last_state_of(X64REGS.FLAGS, FLAG.CF_OVERWRITTEN)
                        self.add_current_line(X64REGS.FLAGS, line_num)

                elif line_operator == "cmc":

                    if last_state != FLAG.CF_MODIFIED:
                        self.set_last_state_of(X64REGS.FLAGS, FLAG.CF_MODIFIED)
                        self.add_current_line(X64REGS.FLAGS, line_num)

                else:   # cmp, test                                             # flags are "lost" if they arent used before an op that changes flags
                    self.set_last_state_of(X64REGS.FLAGS, FLAG.OVERWRITTEN)
                    self.overwrite_move(X64REGS.FLAGS, line_num)
            else:   # doesnt only modify flags. eg: xor, and, add, sub, etc
                self.set_last_state_of(X64REGS.FLAGS, FLAG.OVERWRITTEN)
                self.overwrite_move(X64REGS.FLAGS, line_num)


        if self.x64_operator.explicit_operand_effect != EFFECT.NONE:

            if self.x64_operator.explicit_operand_effect == EFFECT.MODIFIED:
                
                if op_count == 1:

                    target_operand = operand_list[0]
                    if target_operand.data_type == OPERAND_TYPE.REGISTER:

                        if target_operand.mem_accessed:

                            self.add_current_line(X64REGS.MEMORY, line_num)

                            if target_operand.offset_count > 0:                # eg mov dword ptr [rax + r9] = ... 
                                for s_offset in target_operand.offset_list:
                                    dst_off = s_offset[1]
                                    if dst_off in self.registers:
                                        self.save_prior_to_memory(dst_off)

                        instruction_result = self.get_expected_effect(target_operand.size_used, EFFECT.MODIFIED)
                        self.set_last_state_of(target_operand.corresponding_data, instruction_result)
                        self.add_current_line(target_operand.corresponding_data, line_num)
                
                elif op_count == 2:
                    dst_operand = operand_list[0]
                    src_operand = operand_list[1]

                    if dst_operand.data_type == OPERAND_TYPE.REGISTER:  # OP <REG>, ?; <REG> = DST_OPERAND

                        #if dst_operand.corresponding_data == X64REGS.RSP:       # bandaid 'fix'
                            #self.add_current_line(X64REGS.RSP, line_num)

                        if dst_operand.mem_accessed:    ## OP PTR [<REG>], ?; PTR [<REG>] = DST_OPERAND
                            self.save_prior_to_memory(dst_operand.corresponding_data)
                            
                            self.add_current_line(X64REGS.MEMORY, line_num)

                            if dst_operand.offset_count > 0:                # eg mov dword ptr [rax + r9] = ... 
                                for s_offset in dst_operand.offset_list:
                                    dst_off = s_offset[1]
                                    if dst_off in self.registers:
                                        self.save_prior_to_memory(dst_off)

                            if src_operand.data_type == OPERAND_TYPE.REGISTER:          # OP PTR [REG], <REG>
                                self.add_prior_lines_to_from(X64REGS.MEMORY, src_operand.corresponding_data)
                                #instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.MODIFIED)
                                #self.set_last_state_of(dst_operand.corresponding_data, instruction_result)


                                
                                                        
                            else:                                                   # # OP PTR [REG], IMMEDIATE [CAN'T HAVE MEM TO MEM OPS]
                                self.add_current_line(dst_operand.corresponding_data, line_num)
                                
                        
                        else:                       # OP <reg>, ?

                            if src_operand.data_type == OPERAND_TYPE.REGISTER:              # OP <reg>, <reg>

                                #if src_operand.corresponding_data == X64REGS.RSP:       # bandaid 'fix'
                                    #self.add_current_line(X64REGS.RSP, line_num)

                                if src_operand.mem_accessed:

                                    if src_operand.offset_count > 0:                # eg mov dword ptr [rax + r9] = ... 
                                        for s_offset in src_operand.offset_list:
                                            dst_off = s_offset[1]
                                            if dst_off in self.registers:
                                                self.save_prior_to_memory(dst_off)
                                                self.add_prior_lines_to_from(dst_operand.corresponding_data, dst_off)
                                    
                                    self.save_prior_to_memory(src_operand.corresponding_data)
                                    self.add_prior_lines_to_from(dst_operand.corresponding_data, src_operand.corresponding_data)
                                    self.add_current_line(dst_operand.corresponding_data, line_num)

                                elif src_operand.segment_accessed:
                                    x = 0
                                else:   # reg
                                    if src_operand.corresponding_data == dst_operand.corresponding_data:

                                        if dst_operand.size_used == src_operand.size_used:  # same sz 

                                            instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.OVERWRITTEN)

                                            if line_operator == "sub" or line_operator == "sbb" or line_operator == "xor":
                                                if self.get_last_state_of(dst_operand.corresponding_data) <= instruction_result:

                                                    self.set_last_state_of(dst_operand.corresponding_data, instruction_result)
                                                    self.overwrite_move(dst_operand.corresponding_data, line_num)
                                    
                                    else:   # op reg1, reg2; reg1 != reg2
                                        instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.MODIFIED)
                                        self.set_last_state_of(dst_operand.corresponding_data, instruction_result)
                                        self.add_current_line(dst_operand.corresponding_data, line_num)
                                        self.add_prior_lines_to_from(dst_operand.corresponding_data, src_operand.corresponding_data)
                                                    
                            
                            else:   # op <reg>, imm
                                instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.MODIFIED)
                                self.set_last_state_of(dst_operand.corresponding_data, instruction_result)
                                self.add_current_line(dst_operand.corresponding_data, line_num)
                    else:                   # op <some hardcoded data>, ?
                        self.add_current_line(dst_operand.corresponding_data, line_num)


                
                elif op_count == 3:
                    dst_operand = operand_list[0]
                    src_operand = operand_list[1]

            
            elif self.x64_operator.explicit_operand_effect == EFFECT.OVERWRITTEN:

                if op_count == 2:
                    dst_operand = operand_list[0]
                    src_operand = operand_list[1]

                    if dst_operand.data_type == OPERAND_TYPE.REGISTER:                                      # OP reg, ?

                        #if dst_operand.corresponding_data == X64REGS.RSP:       # bandaid 'fix'
                        #    self.add_current_line(X64REGS.RSP, line_num)

                        dst_last_state = self.get_last_state_of(dst_operand.corresponding_data)

                        
                        if dst_operand.mem_accessed:     #write to mem           # OP [reg], ?;

                            self.add_prior_lines_to_from(X64REGS.MEMORY, dst_operand.corresponding_data)    # add lines of curr register being referred to in mem. (not included in offsets)

                            self.add_current_line(X64REGS.MEMORY, line_num) # track line

                            if dst_operand.offset_count > 0:
                                for s_offset in dst_operand.offset_list:
                                    dst_off = s_offset[1]
                                    if dst_off in self.registers: 
                                        self.save_prior_to_memory(dst_off)
                            
                            if src_operand.data_type == OPERAND_TYPE.REGISTER:          # OP PTR [REG], <REG>

                                self.add_prior_lines_to_from(X64REGS.MEMORY, src_operand.corresponding_data)
                                
                            else:                                                   # # OP PTR [REG], IMMEDIATE [CAN'T HAVE MEM TO MEM OPS]
                                x = 0   # covered by add_current_line above
                        
                        else:                       # OP <reg>, ?

                            if src_operand.data_type == OPERAND_TYPE.REGISTER:              # OP <reg>, <reg>

                                

                                

                                if src_operand.mem_accessed:        # op <reg>, [<reg>] # read from mem 

                                    #self.add_prior_lines_to_from(X64REGS.MEMORY, src_operand.corresponding_data)
                            
                                    #self.add_current_line(X64REGS.MEMORY, line_num)

                                    self.overwrite_move_transfer(dst_operand.corresponding_data, src_operand.corresponding_data)
                                    self.add_current_line(dst_operand.corresponding_data, line_num)

                                    if src_operand.offset_count > 0:
                                        for s_offset in src_operand.offset_list:
                                            dst_off = s_offset[1]
                                            if dst_off in self.registers: 
                                                self.add_prior_lines_to_from(dst_operand.corresponding_data, dst_off)
                                                self.save_prior_to_memory(dst_off)

                                elif src_operand.segment_accessed:  # need fix 
                                    self.add_prior_lines_to_from(X64REGS.MEMORY, src_operand.corresponding_data)

                                    self.overwrite_move_transfer(dst_operand.corresponding_data, src_operand.corresponding_data)
                                    self.add_current_line(X64REGS.MEMORY, line_num)
                                else:   # reg

                                    if dst_operand.corresponding_data == X64REGS.RSP:
                                        self.save_prior_to_memory(X64REGS.RSP)

                                    instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.OVERWRITTEN)

                                    
                                    self.overwrite_move_transfer(dst_operand.corresponding_data, src_operand.corresponding_data)
                                    self.set_last_state_of(dst_operand.corresponding_data, instruction_result)
                                    self.add_current_line(dst_operand.corresponding_data, line_num)
                            
                            else:   # op <reg>, imm
                                instruction_result = self.get_expected_effect(dst_operand.size_used, EFFECT.OVERWRITTEN)
                                self.set_last_state_of(dst_operand.corresponding_data, instruction_result)
                                self.overwrite_move(dst_operand.corresponding_data, line_num)
                    else:                   # op <some hardcoded data>, ?
                        x =0                        # op reg, [reg]

                        self.add_current_line(X64REGS.SPECIAL, line_num)
        
        else:
            if self.x64_operator.implicit_change != IMPLICIT_OP.NONE:

                if self.x64_operator.implicit_change == IMPLICIT_OP.CPUID:  # EAX, EBX, ECX, EDX

                    self.overwrite_move(X64REGS.RAX, line_num)
                    self.set_last_state_of(X64REGS.RAX, REG_STATE.OVERWRITTEN_QWORD)

                    self.overwrite_move(X64REGS.RBX, line_num)
                    self.set_last_state_of(X64REGS.RBX, REG_STATE.OVERWRITTEN_QWORD)

                    self.overwrite_move(X64REGS.RCX, line_num)
                    self.set_last_state_of(X64REGS.RCX, REG_STATE.OVERWRITTEN_QWORD)

                    self.overwrite_move(X64REGS.RDX, line_num)
                    self.set_last_state_of(X64REGS.RDX, REG_STATE.OVERWRITTEN_QWORD)

                elif self.x64_operator.implicit_change == IMPLICIT_OP.CBW_CWDE_CDQE:    # sign extend RAX
                    
                    if line_operator == "cbw":
                        self.set_last_state_of(X64REGS.RAX, REG_STATE.MODIFIED_WORD)
                    
                    elif line_operator == "cwde":
                        self.set_last_state_of(X64REGS.RAX, REG_STATE.MODIFIED_DWORD)
                    
                    elif line_operator == "cdqe":
                        self.set_last_state_of(X64REGS.RAX, REG_STATE.MODIFIED_QWORD)
                    
                    self.add_current_line(X64REGS.RAX, line_num)

                elif self.x64_operator.implicit_change == IMPLICIT_OP.CWD_CDQ_CQO:  # sign extend RDX using RAX

                    if line_operator == "cwd":
                        self.set_last_state_of(X64REGS.RDX, REG_STATE.OVERWRITTEN_WORD)

                    elif line_operator == "cdq":
                        self.set_last_state_of(X64REGS.RDX, REG_STATE.OVERWRITTEN_DWORD)

                    elif line_operator == "cqo":
                        self.set_last_state_of(X64REGS.RDX, REG_STATE.OVERWRITTEN_QWORD)

                    self.overwrite_move_transfer(X64REGS.RDX, X64REGS.RAX)
                    self.add_current_line(X64REGS.RDX, line_num)

                elif self.x64_operator.implicit_change == IMPLICIT_OP.RDTSC: # EDX:EAX | high order 32 bits of msr in edx. low order in eax
                    self.overwrite_move(X64REGS.RAX, line_num)
                    self.set_last_state_of(X64REGS.RAX, REG_STATE.OVERWRITTEN_QWORD)

                    self.overwrite_move(X64REGS.RDX, line_num)
                    self.set_last_state_of(X64REGS.RDX, REG_STATE.OVERWRITTEN_QWORD)


                elif self.x64_operator.implicit_change == IMPLICIT_OP.LAHF:     # store FLAGS into AH
                    self.overwrite_move_transfer(X64REGS.RAX, X64REGS.FLAGS)
                    self.set_last_state_of(X64REGS.RAX, REG_STATE.OVERWRITTEN_WORD)


                elif self.x64_operator.implicit_change == IMPLICIT_OP.SAHF:     # store AH into FLAGS: bits 7[SF], 6[ZF], 4[AF], 2[PF], 0[CF] reads from rax
                    self.overwrite_move_transfer(X64REGS.FLAGS, X64REGS.RAX)
                    self.set_last_state_of(X64REGS.FLAGS, FLAG.OVERWRITTEN)

            else:

                if line_operator == "lock" or line_operator == "prefetch" \
                or line_operator == "prefetchw" or line_operator == "jmp" or line_operator == "syscall":
                    self.add_current_line(X64REGS.SPECIAL, line_num)
        '''
        for reg in self.registers:
            print(f"after run....----------------\n")
            if reg in self.registers:
                print(f"{reg}: {self.registers[reg].live_lines.sequence}\n")
        print(f"{line_operator} {operand_list} {line_num}\n")            
        '''
        

    def get_last_state_of(self, register):
        if register in self.registers:
            return self.registers[register].last_state
    
    def set_last_state_of(self, register, some_state):
        if register in self.registers:
            self.registers[register].last_state = some_state

    def overwrite_move(self, target_operand, line_num):
        self.registers[target_operand].live_lines.reset()
        self.add_current_line(target_operand, line_num)

    def overwrite_move_transfer(self, dst_operand, src_operand):
        # first need to "dump" old vals aka replace. then add 
        self.registers[dst_operand].live_lines.replace_with(self.registers[src_operand].live_lines)
    

    def add_current_line(self, target_operand, line_num):

        if target_operand not in self.registers:
            if DEBUG_MSGS:
                print(f"invalid operand detected! provided arguments: arg1 (target_operand) = {target_operand}\n arg2 (line_num) = {line_num}\n")
        else:
            self.registers[target_operand].live_lines.add_link(line_num)
    
    def add_prior_lines_to_from(self, dst_operand, src_operand):
        self.registers[src_operand].live_lines.transfer_to(self.registers[dst_operand].live_lines)
    
    def save_prior_to_memory(self, target_operand):
        self.registers[target_operand].live_lines.transfer_to(self.registers[X64REGS.MEMORY].live_lines)

