import re

from .fx64_patterns import REGEXPATTERNS

from .fx64_operands import FLAG, IMPLICIT_OP, EFFECT



class x86_flags:
    def __init__(self):
        self.flags = {}
        '''
        self.CF_affected = FLAG.NO_CHANGE     # Carry Flag
        self.ZF_affected = FLAG.NO_CHANGE     # Zero Flag
        self.SF_affected = FLAG.NO_CHANGE     # Sign Flag
        self.OF_affected = FLAG.NO_CHANGE     # Overflow Flag
        self.PF_affected = FLAG.NO_CHANGE     # Parity Flag
        self.AF_affected = FLAG.NO_CHANGE     # 
        self.DF_affected = FLAG.NO_CHANGE
        '''
        self.init_entries()
        self.requires_flag_val = False
        self.flags_affected = False

        self.does_cur_line_set_flags = False 
        self.was_modified_flag_val_used_before_change = False
        self.does_cur_line_depend_on_flag = False 
        self.was_flags_modified_before = False
    
    def reset(self):
        self.init_entries()
        self.requires_flag_val = False
        self.flags_affected = False
        
    
    def init_entries(self):
        self.flags["c"] = FLAG.NO_CHANGE
        self.flags["s"] = FLAG.NO_CHANGE
        self.flags["z"] = FLAG.NO_CHANGE
        self.flags["o"] = FLAG.NO_CHANGE
        self.flags["p"] = FLAG.NO_CHANGE
        self.flags["a"] = FLAG.NO_CHANGE
        self.flags["d"] = FLAG.NO_CHANGE

    def set_flags(self, af, cf, df, of, pf, sf, zf):
        self.flags["a"] = af
        self.flags["c"] = cf
        self.flags["d"] = df
        self.flags["o"] = of
        self.flags["p"] = pf
        self.flags["s"] = sf
        self.flags["z"] = zf

    def output_status(self):
        if self.requires_flag_val:
            print("INSTRUCTION REQUIRES FLAG VALUE")
        for sf in self.flags:
            if self.flags[sf] == FLAG.MODIFIED:
                message = "MODIFIED"
            elif self.flags[sf] == FLAG.CLEARED:
                message = "CLEARED"
            elif self.flags[sf] == FLAG.NO_CHANGE:
                message = "NOT CHANGED"
            elif self.flags[sf] == FLAG.UNDEFINED:
                message = "UNDEFINED"
            if sf == "a":
                print(f"AF is {message}")
            elif sf == "c":
                print(f"CF is {message}")
            elif sf == "d":
                print(f"DF is {message}")
            elif sf == "o":
                print(f"OF is {message}")
            elif sf == "p":
                print(f"PF is {message}")
            elif sf == "s":
                print(f"SF is {message}")
            elif sf == "z":
                print(f"ZF is {message}")

'''
    def check_not_cfzf(self): #A = ABOVE		| NBE = NOT BELOW OR EQUAL		CF = 0 AND ZF = 0
        return (not self.flags["c"]) and (not self.flags["z"]) 

    def check_not_cf(self): #AE = ABOVE OR EQUAL	| NB = NOT BELOW	| NC = NOT CARRY	CF = 0
        return not self.flags["c"]
    
    def check_not_pf(self):  
        return not self.flags["p"]
    
    def check_not_zf(self):  
        return not self.flags["z"]
    
    def check_cf(self): # B = BELOW		| C = CARRY 		| NAE = NOT ABOVE OR EQUAL	CF = 1
        return self.flags["c"]
    
    def check_pf(self):  
        return self.flags["p"]
    
    def check_cf_or_zf(self):   # BE= BELOW OR EQUAL	| NA = NOT ABOVE			CF = 1 OR ZF = 1
        return (self.flags["c"] or self.flags["z"])
    
    def check_zf(self): # E = EQUAL		| Z = ZERO				ZF = 1
        return self.flags["z"]

    def check_not_zf_and_sf_of(self): # G = GREATER 		| NLE = NOT LESS OR EQUAL		ZF = 0 AND SF = OF
        return (not self.flags["z"]) and (self.flags["s"] == self.flags["o"])
    
    def check_sf_of(self): # GE = GREATER OR EQUAL	| NL = NOT LESS				SF = OF
        return (self.flags["s"] == self.flags["o"])

    def check_sf_not_of(self): #L = LESS 		| NGE = NOT GREATER OR EQUAL		SF != OF
        return (self.flags["s"] != self.flags["o"])
'''    

#log last instruction that modified flags
class x86_ops:
    def __init__(self):
        self.rflags = x86_flags()   

        self.flag_val_actually_used = False

        self.only_modifies_flags = False
        self.implicit_change = IMPLICIT_OP.NONE

        self.involves_stack = False
        self.explicit_operand_effect = EFFECT.NONE
        self.corresponding_op = ""

        self.unk_operators = {}
    
    def reset(self):
        self.involves_stack = False
        self.explicit_operand_effect = EFFECT.NONE
        self.implicit_change = IMPLICIT_OP.NONE
        self.corresponding_op = ""
        self.rflags.reset()
 

    def id_op(self, operator):

        self.explicit_operand_effect = EFFECT.NONE
        self.rflags.requires_flag_val = False
        self.only_modifies_flags = False
        self.implicit_change = IMPLICIT_OP.NONE
        self.corresponding_op = operator
        self.involves_stack = False
        if re.search(REGEXPATTERNS.PATTERN_NO_FLAGS_MODIFIED, operator):

            self.rflags.flags_affected = False
            self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)


            if re.search(r'(rep.*)', operator):
                self.rflags.requires_flag_val = True
        
            

            # popfq shouldnt be detected by regex above
            if operator == "pushfq" or operator == "popfq" or operator == "pop" or operator == "push" or operator == "ret" or operator == "call": # <- FIX 
                self.involves_stack = True

                if operator == "pushfq":
                    self.rflags.requires_flag_val = True
                elif operator == "push":
                    self.explicit_operand_effect = EFFECT.NONE  # <- FIX
                elif operator == "popfq":
                    self.only_modifies_flags = True
                    self.rflags.flags_affected = True
                    self.rflags.set_flags(FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN)
                elif operator == "pop":
                    self.explicit_operand_effect = EFFECT.OVERWRITTEN

            if operator == 'mov' or operator == 'movsx' or operator == 'movsxd' or operator == 'movzx' or operator == 'movabs' \
               or operator == 'lea' or operator == 'xchg':
                self.explicit_operand_effect = EFFECT.OVERWRITTEN
            
            elif operator == 'bswap' or operator == 'not':
                self.explicit_operand_effect = EFFECT.MODIFIED
            #elif operator == 'push':
            #    self.explicit_operand_effect = EFFECT.NONE    # <- FIX 
            elif re.search('set', operator):
                self.explicit_operand_effect = EFFECT.MODIFIED

                
            ##print(f"in NO PATTERN MODIFIED section for op {operator} with len: {len(operator)}")
            if re.fullmatch(REGEXPATTERNS.PATTERN_CC_CF_SET, operator):
                ##print("Checks if CF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_PF_SET, operator):
                ##print("Checks if PF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_ZF_SET, operator):
                ##print("Checks if ZF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_OF_SET, operator):
                ##print("Checks if OF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_CF_NOT_SET, operator):
                #print("Checks if CF == 0")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_PF_NOT_SET, operator):
                #print("Checks if PF == 0")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_ZF_NOT_SET, operator):
                #print("Checks if ZF == 0")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_OF_NOT_SET, operator):
                #print("Checks if OF == 0")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_SF_SET, operator):
                #print("Checks if SF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_SF_NOT_SET, operator):
                #print("Checks if SF == 0")
                self.rflags.requires_flag_val = True
            
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_CF_AND_ZF_NOT_SET, operator):
                #print("Checks if CF AND ZF == 0")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_CF_OR_ZF_SET, operator):
                #print("Checks if CF OR ZF == 1")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_OF_EQUAL_SF, operator):
                #print("Checks if OF == SF")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_OF_NOT_EQUAL_SF, operator):
                #print("Checks if OF != SF")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_OF_EQUAL_SF_AND_ZF_NOT_SET, operator):
                #print("Checks if ZF == 0 AND SF == OF")
                self.rflags.requires_flag_val = True
            elif re.fullmatch(REGEXPATTERNS.PATTERN_CC_ZF_SET_OR_OF_NOT_EQUAL_SF, operator):
                #print("Checks if ZF == 1 OR SF != OF")
                self.rflags.requires_flag_val = True
            
 

            elif re.search(r'cpuid', operator):
                #print("cpuid")
                self.implicit_change = IMPLICIT_OP.CPUID
            elif re.search(r'(cbw)|(cwde)|(cdqe)', operator):
                #print("signextend RAX form; modifies RAX")
                self.implicit_change = IMPLICIT_OP.CBW_CWDE_CDQE
            elif re.search(r'cwd|cdq|cqo', operator):
                #print("signextend respective RAX form to RDX reg; modifies RDX")
                self.implicit_change = IMPLICIT_OP.CWD_CDQ_CQO
            elif re.search(r'rdtsc', operator):
                self.implicit_change = IMPLICIT_OP.RDTSC
            elif re.search(r'lahf', operator):
                self.implicit_change = IMPLICIT_OP.LAHF
                self.rflags.requires_flag_val = True
            elif re.search(r'sahf', operator):
                self.implicit_change = IMPLICIT_OP.SAHF
                self.only_modifies_flags = True
                self.rflags.flags_affected = True
            
        elif re.search(r'(adc)|(add)|(sub)|(sbb)|(cmp)|(xadd)', operator):  # modifies OF, SF, ZF, AF, CF, PF
            self.rflags.flags_affected = True

            self.rflags.set_flags(FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN)

            if operator != 'cmp':
                self.explicit_operand_effect = EFFECT.MODIFIED
            else:
                self.explicit_operand_effect = EFFECT.NONE 
                self.only_modifies_flags = True
        
        elif re.search(r'(and)|(or)|(xor)|(test)', operator):   # modifies SF, ZF, PF, and OF = CF = 0
            self.rflags.flags_affected = True

            self.rflags.set_flags(FLAG.UNDEFINED, FLAG.CLEARED, FLAG.NO_CHANGE, FLAG.CLEARED, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN)
            
            if operator != 'test':
                self.explicit_operand_effect = EFFECT.MODIFIED
            else:
                self.explicit_operand_effect = EFFECT.NONE
                self.only_modifies_flags = True
        elif re.search(r'(clc)|(cmc)|(stc)', operator): # only CF modified. CLC = Clear CF | CMC = Complement CF | STC = Set CF
            self.rflags.flags_affected = True
            self.only_modifies_flags = True

            if operator[1] == 'm':  # CMC LOL 
                self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.MODIFIED, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)
            else:
                self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)

            
        elif re.search(r'(cld)|(std)', operator):   # only DF modified
            self.rflags.flags_affected = True
            self.only_modifies_flags = True

            self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)
        elif re.search(r'(dec)|(inc)', operator): # NOT set CF every other flag yes
            self.rflags.flags_affected = True

            self.explicit_operand_effect = EFFECT.MODIFIED
            self.rflags.set_flags(FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN)
        
        elif re.search(r'(neg)', operator):
            self.rflags.flags_affected = True
            # if operand == 0, CF = 0. ELSE CF = 1
            self.explicit_operand_effect = EFFECT.MODIFIED
            self.rflags.set_flags(FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN, FLAG.OVERWRITTEN)

        elif re.search(r'(rdrand)|(rdseed)', operator): # sets CF according to result. OF = SF = AF = ZF = PF = 0
            self.rflags.flags_affected = True

            self.rflags.set_flags(FLAG.CLEARED, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.CLEARED, FLAG.CLEARED, FLAG.CLEARED, FLAG.CLEARED)
        elif re.search(r'(i?mul)', operator):   # modifies OF and CF [0 if upper half is 0] AX, register pair DX:AX, or register pair EDX:EAX (depending on the operand size)
            self.rflags.flags_affected = True

            self.explicit_operand_effect = EFFECT.MODIFIED
            self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)
        elif re.search(r'(i?div)', operator):   # modifies RDX:RAX flags undefined.
            self.rflags.flags_affected = True

            self.explicit_operand_effect = EFFECT.MODIFIED
            self.rflags.set_flags(FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.NO_CHANGE, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.UNDEFINED)
        elif re.search(r'(s(a|h)(l|r)d?)', operator): #The SF, ZF, and PF flags are set according to the result. If the count is 0, the flags are not affected.
        # The CF flag contains the value of the last bit shifted out of the destination operand; it is undefined for SHL and SHR instructions where the count is greater than or equal to the size (in bits) 
        # of the destination operand. The OF flag is affected only for 1-bit shifts (see “Description” above); otherwise, it is undefined. 
            self.rflags.flags_affected = True

            self.explicit_operand_effect = EFFECT.MODIFIED
            self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.MODIFIED, FLAG.NO_CHANGE, FLAG.MODIFIED, FLAG.MODIFIED, FLAG.MODIFIED, FLAG.MODIFIED)
        elif re.search(r'r(c|o)(l|r)', operator): # if masked count == 0, no flags modified. 1 then OF modified. > 1 then OF undefined. CF modified if >= 1. SF ZF AF PF not modified.
            self.rflags.flags_affected = True
            self.explicit_operand_effect = EFFECT.MODIFIED
    


            self.rflags.set_flags(FLAG.NO_CHANGE, FLAG.MODIFIED, FLAG.NO_CHANGE, FLAG.MODIFIED, FLAG.NO_CHANGE, FLAG.NO_CHANGE, FLAG.NO_CHANGE)
        elif re.search(r'(bt(c|r|s)?)', operator): # The CF flag contains the value of the selected bit. The ZF flag is unaffected. The OF, SF, AF, and PF flags are undefined.
            if len(operator) == 2: # bt lol 
                self.explicit_operand_effect = EFFECT.NONE
                
            else:
                self.explicit_operand_effect = EFFECT.MODIFIED
                
            self.rflags.flags_affected = True
 
            self.rflags.set_flags(FLAG.UNDEFINED, FLAG.OVERWRITTEN, FLAG.NO_CHANGE, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.UNDEFINED)
        elif re.search(r'(bs(f|r))', operator): # The ZF flag is set to 1 if the source operand is 0; otherwise, the ZF flag is cleared. The CF, OF, SF, AF, and PF flags are undefined.
            self.rflags.flags_affected = True

            self.explicit_operand_effect = EFFECT.OVERWRITTEN
            self.rflags.set_flags(FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.NO_CHANGE, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.UNDEFINED, FLAG.OVERWRITTEN)
        
    
        else:
             
            if re.search(r'call', operator):
                self.involves_stack = True
                #print("RIP modified.")
        
            else:
                #print(f"op not registered: {operator} {type(operator)}")
                if operator not in self.unk_operators:
                    self.unk_operators[operator] = 0
                self.unk_operators[operator] += 1
                
