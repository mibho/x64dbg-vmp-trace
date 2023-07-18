class X64REGS:
    RAX = 'rax'
    RBX = 'rbx'
    RCX = 'rcx'
    RDX = 'rdx'

    RDI = 'rdi'
    RSI = 'rsi'

    RIP = 'rip'
    RSP = 'rsp'
    RBP = 'rbp'

    R8 = 'r8'
    R9 = 'r9'
    R10 = 'r10'
    R11 = 'r11'
    R12 = 'r12'
    R13 = 'r13'
    R14 = 'r14'
    R15 = 'r15'
    FLAGS = 'flags'
    SPECIAL = 'special'
    MEMORY = 'memory'

class FLAG:
    NOTSET = -1
    UNDEFINED = -1
    NO_CHANGE = 11
    CLEARED = 12
    MODIFIED = 13
    OVERWRITTEN = 14

    CF_MODIFIED = 15
    CF_OVERWRITTEN = 16

    DF_MODIFIED = 17
    DF_OVERWRITTEN = 18

class IMPLICIT_OP:
    NONE            = -1
    CPUID           = 1
    CBW_CWDE_CDQE   = 2
    CWD_CDQ_CQO     = 3
    RDTSC           = 4
    LAHF            = 5
    SAHF            = 6

class EFFECT:
    NONE = -1
    MODIFIED = 1
    OVERWRITTEN = 2


class OPERAND_TYPE:
    NOT_SET = -1
    CONSTANT = 0
    ADDRESS = 0
    
    REGISTER = 1

class REG_SIZE:
    NOT_SET = -2
    IGNORE = -1
    BYTE = 10
    LOBYTE = 10
    HIBYTE = 11
    

    WORD = 12
    
    DWORD = 13

    QWORD = 14

    M128  = 15

class REG_TYPE:
    NOT_SET = 'uhohtest'
    IGNORE = 'yikesnotgood'
    RAX = 'rax'
    RBX = 'rbx'
    RCX = 'rcx'
    RDX = 'rdx'

    RDI = 'rdi'
    RSI = 'rsi'
    RSP = 'rsp'
    RBP = 'rbp'

    R8  = 'r8'
    R9  = 'r9'
    R10 = 'r10'
    R11 = 'r11'
    R12 = 'r12'
    R13 = 'r13'
    R14 = 'r14'
    R15 = 'r15'

    RIP = 'rip'


# "special" regs. still consider covering
#where's CR1, 5, etc? they result in undefined behavior 
    CR0 = 'cr0'
    CR2 = 'cr2'
    CR3 = 'cr3'
    CR4 = 'cr4'
    CR8 = 'cr8'

class SEGMENT_TYPE:
    '''
    CS 	Code Segment
    DS 	Data Segment
    SS 	Stack Segment
    ES 	Extra Segment (used for string operations)
    FS 	General-purpose Segment
    GS 	General-purpose Segment 
    '''
    NOPE = '1000'
    CS = 'cs'
    DS = 'ds'
    SS = 'ss'
    ES = 'es'
    FS = 'fs'
    GS = 'gs'



class operand:

    def __init__(self):
        self.data_type = OPERAND_TYPE.NOT_SET
        self.size_used = REG_SIZE.NOT_SET
        self.corresponding_data = ""
        self.operand_set = False

        self.mem_accessed = False   # no mem access? no offsets

        self.segment_accessed = False
        self.segment_type = SEGMENT_TYPE.NOPE

        self.offset_list = []
        self.offset_count = 0
    
    def rebuild_offset(self, offset_list):
        result = ""
        if len(offset_list) > 0:
            for i in range(0,len(offset_list)):
                sign = offset_list[i][3]
                coefficient = offset_list[i][2]
                offset_val = offset_list[i][1]

                if i != 0 and i != len(offset_list):
                    result += " " + sign + " "
                else:
                    if sign == "-":
                        result += " - "

                if offset_list[i][0] == OPERAND_TYPE.REGISTER:
                    if coefficient != None:
                        result += str(coefficient) + offset_val
                    else:
                        result += offset_val
                else:
                    result += offset_val
    # if mem accessed without any additional offsets, it's just mem acc on register
                
        return result
    
    def return_op_type_str(self):
        if self.data_type == OPERAND_TYPE.NOT_SET:
            return "NOT set"
        elif self.data_type == OPERAND_TYPE.CONSTANT:
            return "Constant or Address"
        elif self.data_type == OPERAND_TYPE.REGISTER:
            return "register"
        else:
            return "well something broke"
    
    def is_operand_set(self):
        return self.operand_set
    
    def get_operand_type(self):
        return self.data_type
    
    def get_specified_size(self):
        return self.size_used
    
    def get_data(self):
        return self.corresponding_data
    
    def has_offsets(self):
        return self.offset_count != 0
    
    def operand_val_set(self):
        self.operand_set = True

    def set_operand_type(self, valuetype):
        self.data_type = valuetype
    
    
    
    def set_specified_size(self, regsize):
        self.size_used = regsize
    
    
    
    def set_data(self, gpr):
        self.corresponding_data = gpr
    
    
    
    def add_offset(self, data_type, offset, coefficient, sign):
        self.offset_list.append((data_type, offset, coefficient, sign))
        self.offset_count += 1
    
    
    
    def set_mem_ref(self, m_acc, s_acc = False, s_type = SEGMENT_TYPE.NOPE):
        self.mem_accessed = m_acc
        self.segment_accessed = s_acc
        self.segment_type = s_type
    
    def output(self):
        print(f"(data type: {self.data_type})")
        print(f"(siez used: {self.size_used})")
        print(f"(corresponding reg : {self.corresponding_data})")
        print(f"(mem_access: {self.mem_accessed})")
        print(f"offset count: {self.offset_count}")
        if self.offset_count > 0:
            for x in self.offset_list:
                print(f"offset: {x}")
        print(f"operand set?: {self.operand_set}")