class REGEXPATTERNS:

    PATTERN_X64_ADDR = r'([a-f|A-F]|\d){12}'    #filter a sequence of (a-f lower+uppercase w/ digits)
    PATTERN_X64_REGS = r'((e|r)?(a|d|s|c|b|1|8|9)+(x|i|0|p|2|3|4|5|w|l)?(l|w)?)'
    PATTERN_REGS = r'r15d|r15w|r15b|r14d|r14w|r14b|r13d|r13w|r13b|r12d|r12w|r12b|r11d|r11w|r11b|r10d|r10w|r10b|r9d|r9w|r9b|r8d|r8w|r8b|rax|eax|ax|al|rdi|edi|dil|di|rsi|esi|sil|si|rdx|edx|dx|dl|rcx|ecx|cx|cl|r8|r9|r10|rsp|esp|spl|sp|rbx|ebx|bx|bl|rbp|ebp|bpl|bp|r12|r13|r11|r14|r15'
    PATTERN_X64_ADDR_ACCESS = r'\[.*(\+|\-)?\]'
    PATTERN_NOT_BB = r'(j.*)|(ret)|(call)'
    PATTERN_OP_FIVE_CHAR = r'((movsx)|(movzx)|(bswap)|(rdtsc)|(setns)|(setne)|(xorps)|(xorpd)|(subps)|(subpd)|(subsd)|(subss)|(stosw)|(stosq)|(stosd)|(stosb)|(repne)|(repnz))'

    PATTERN_DEC_CONSTANT = r'^\d+'

    PATTERN_RAX_SUBSET = r'((e|r)?(ax))|(a(h|l))'   # RAX  | EAX  | AX  | AH | AL
    PATTERN_RBX_SUBSET = r'((e|r)?(bx))|(b(h|l))'   # RBX  | EBX  | BX  | BH | BL
    PATTERN_RCX_SUBSET = r'((e|r)?(cx))|(c(h|l))'   # RCX  | ECX  | CX  | CH | CL
    PATTERN_RDX_SUBSET = r'((e|r)?(dx))|(d(h|l))'   # RDX  | EDX  | DX  | DH | DL

    PATTERN_RDI_SUBSET = r'((e|r)?(di)(l)?)'        # RDI  | EDI  | DI  | DIL
    PATTERN_RSI_SUBSET = r'((e|r)?(si)(l)?)'        # RSI  | ESI  | SI  | SIL
    PATTERN_RSP_SUBSET = r'((e|r)?(sp)(l)?)'        # RSP  | ESP  | SP  | SPL
    PATTERN_RBP_SUBSET = r'((e|r)?(bp)(l)?)'        # RBP  | EBP  | BP  | BPL

    PATTERN_R8_SUBSET = r'(((r)8)(b|w|d)?)'         # r8  | r8d  | r8w  | r8b 
    PATTERN_R9_SUBSET = r'(((r)9)(b|w|d)?)'         # r9  | r9d  | r9w  | r9b
    PATTERN_R10_SUBSET = r'(((r)10)(b|w|d)?)'       # r10 | r10d | r10w | r10b
    PATTERN_R11_SUBSET = r'(((r)11)(b|w|d)?)'       # r11 | r11d | r11w | r11b
    PATTERN_R12_SUBSET = r'(((r)12)(b|w|d)?)'       # r12 | r12d | r12w | r12b
    PATTERN_R13_SUBSET = r'(((r)13)(b|w|d)?)'       # r13 | r13d | r13w | r13b
    PATTERN_R14_SUBSET = r'(((r)14)(b|w|d)?)'       # r14 | r14d | r14w | r14b
    PATTERN_R15_SUBSET = r'(((r)15)(b|w|d)?)'       # r15 | r15d | r15w | r15b 

    PATTERN_CC_CF_SET                       = r'(((set)|(cmov)|j))(b|c|nae)'        # CF = 1
    PATTERN_CC_PF_SET                       = r'(((set)|(cmov)|j))(p(e)?)'          # PF = 1
    PATTERN_CC_ZF_SET                       = r'(((set)|(cmov)|j))(e|z)'            # ZF = 1
    PATTERN_CC_OF_SET                       = r'(((set)|(cmov)|j))o'                # OF = 1
    PATTERN_CC_SF_SET                       = r'(((set)|(cmov)|j))s'                # SF = 1

    PATTERN_CC_CF_NOT_SET                   = r'(((set)|(cmov)|j))(ae|(n(b|c)))'    # CF = 0 
    PATTERN_CC_PF_NOT_SET                   = r'(((set)|(cmov)|j))(np|po)'          # PF = 0
    PATTERN_CC_ZF_NOT_SET                   = r'(((set)|(cmov)|j))(n(e|z))'         # ZF = 0
    PATTERN_CC_OF_NOT_SET                   = r'(((set)|(cmov)|j))no'               # OF = 0
    PATTERN_CC_SF_NOT_SET                   = r'(((set)|(cmov)|j))ns'               # SF = 0

    PATTERN_CC_CF_AND_ZF_NOT_SET            = r'(((set)|(cmov)|j))(a|nbe)'          # CF = 0 AND ZF = 0
    
    PATTERN_CC_CF_OR_ZF_SET                 = r'(((set)|(cmov)|j))(be|na)'          # CF = 1 OR ZF = 1
    
    
    PATTERN_CC_OF_EQUAL_SF                  = r'(((set)|(cmov)|j))(ge|nl)'          # SF = OF
    PATTERN_CC_OF_NOT_EQUAL_SF              = r'(((set)|(cmov)|j))(l|nge)'          # SF != OF
    
    PATTERN_CC_OF_EQUAL_SF_AND_ZF_NOT_SET   = r'(((set)|(cmov)|j))(g|nle)'          # ZF = 0 AND SF = OF
    PATTERN_CC_ZF_SET_OR_OF_NOT_EQUAL_SF    = r'(((set)|(cmov)|j))(ng|le)'          # ZF = 1 OR SF != OF

    PATTERN_TEST = r'[er]?((ip)|(([abcd][hlx])|(([ds]i)|([bs]p)l?))|(r(8|9|1[012345])[bwd]?))'
    PATTERN_TEST2 = r'[er]?((ip)|(([abcd][hlx])|((([ds]i)|([bs]p))l?))|(r(8|9|1[012345])[bwd]?))'
    PATTERN_TEST3 = r'[er]?((ip)|([abcd]((x)|(h)|(l)))|(([bds])([ip])(l)?)|(8|9|(1[012345]))([bwd])?)'
    PATTERN_NO_FLAGS_MODIFIED = r'(j[a-zA-Z]{1,2})|(ret)|(((set)|(c)?mov((z?s?x?d?))(a|b|g|l)?))(n?(a|b|c|e|g|l|o|p|s|z){1,2})?|(bswap)|(cbw)|(cwde?)|(cdqe?)|(cqo)|(cpuid)|(lahf)|(lea)|(lods(b|w|q)?)|(loop)|(push)|(pop)|(rdtsc)|(xchg)|((rep((e|z)?|(ne|nz)?)))|(not)|(rep.*)'
