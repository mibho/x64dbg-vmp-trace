'''

p1: Odd or even?

p2: Prime or Not?   [then what about odds that arent prime? are prime?]

p3: divisible by x? or divisible by x_0, ... , x_n? 

p4: starting digit of number 0-9. 10 potential 'encodings' 

p5: 

'''


'''
rsi - 99% bytecode ptr ; how to differentiate when not 

rsp - always on stack

1) first via unique blocks. ONLY braindead indicators:  

            eg: mov rax, rsp    | YES stack related
                lea r10, [rsp + 0x140] | YES stack related

    - keep track of which instruction responsible of changing last flag val.

1a) is reg associated with a certain type?     


if bytecode is read, this reg is most likely related to VIP.
is the same register used as part of push ret? or jmp qword?


main categories

check len of block.

    if len(block) == 1 and end instruction of block is one of the following:
        next_instruction_related = True

            ret, jmp reg, jmp ptr, call
    
    if len(block) == 2:
    
        if push and then call
            most likely VM entry encrypted addr
        
        if push and then ret, 
            next_instruction_related = True


main 1:
    1) last instr of block 

        call related
            type_specific_address
            type_explicit_rip_relative
            type_register
    
    2) last instr of block

        just ret related
            type_alternate_call
    3) 

        control flow related. 
            identify by branch condition or dst?
            maybe branch...

    need readjust to easily get RIP and corresponding order it was executed from start

        
    

    if LEA
        - means load addr or quick math trick


property 1: block ending

    Call

        CALL_TYPE_LABEL                     call 0x1235678
        CALL_TYPE_EXPLICIT_RIP_RELATIVE     call qword ptr [rip + 0x1234]
        CALL_TYPE_REGISTER                  call rax
        CALL_TYPE_MEMORY                    call qword ptr [rax]

    ret
        RET_TYPE_DEFAULT                     ret
        RET_TYPE_GONEXT                     push qword ptr[r11 + r10*8], ret

        
    test - SF, ZF, PF;   CF = OF = 0;   AF = ? u/d
        
        test reg1, reg2 
        
            result = reg1 & reg2
        ---------------------------------------------------------------
        same operands

            test eax, eax   [eax & eax == ?]
            JE/JZ <label>

                if(eax == 0) GOTO <label>
        ------------------------------------------------------------------
        diff operands

            test reg1, reg2     [reg1 & reg2 == ?]
            JE/JZ <label>

                if(reg1 == 0 || reg2 == 0) GOTO <label> 

    cmp - SF, ZF, PF, CF, OF, AF

        cmp reg1, reg2 

            result = reg1 - reg2
                set flags according to result 
                
1 byte = 8 bits...
==========================================================================================================================================================

    EFLAGS      http://www.c-jump.com/CIS77/ASM/Instructions/I77_0070_eflags_bits.htm

    BIT     LABEL
    ---     -----
    0 	    CF 	Carry Flag: 
    
            Set by arithmetic instructions which generate either a carry or borrow. 
            Set when an operation generates a carry to or a borrow from a destination operand.

    2 	    PF 	Parity flag: https://en.wikipedia.org/wiki/Parity_flag

            PARITY FLAG REFLECTS PARITY OF ONLY LEAST SIGNIFICANT BYTE.
    
            Set by most CPU instructions if the least significant (aka the low-order bits) 
            of the destination operand contain an even number of 1's.

                eg:
                    18 + 8 = 26. 
                    
                    26 in binary is 11010. <--- (3 bits are 1s aka set. which is odd.)
                    since result of the operation resulted in ODD # of bits set, PF NOT set. [PF = 0]

                    18 - 8 = 10.

                    10 in binary is 1010  <---- (2 bits are 1s aka set. which is even.)
                    since result of the operation resulted in EVEN # of bits set, PF SET. [PF = 1]



    4 	    AF 	Auxiliary Carry Flag: 
    
            Set if there is a carry or borrow involving bit 4 of EAX. Set when a CPU instruction 
            generates a carry to or a borrow from the low-order 4 bits of an operand. 
            
            This flag is used for binary coded decimal (BCD) arithmetic.

                - only looks at last 4 bits of EAX reg.


    6 	    ZF 	Zero Flag: 
    
            Set by most instructions if the result an operation is binary zero.


    7 	    SF 	Sign Flag: 
    
            Most operations set this bit the same as the most significant bit (aka high-order bit) of the result. 
            0 is positive, 1 is negative.


    8 	    TF 	Trap Flag: 
    
            (sometimes named a Trace Flag.) Permits single stepping of programs. 
            After executing a single instruction, the processor generates an internal exception 1. 
            When Trap Flag is set by a program, the processor generates a single-step interrupt after each instruction. 
            A debugging program can use this feature to execute a program one instruction at a time.


    9 	    IF 	Interrupt Enable Flag: 
    
            when set, the processor recognizes external interrupts on the INTR pin. 
            When set, interrupts are recognized and acted on as they are received. 
            The bit can be cleared to turn off interrupt processing temporarily.


    10 	    DF 	Direction Flag: 
    
            Set and cleared using the STD and CLD instructions. It is used in string processing. 
            When set to 1, string operations process down from high addresses to low addresses. 
            If cleared, string operations process up from low addresses to high addresses.


    11 	    OF 	Overflow Flag:
    
            Most arithmetic instructions set this bit, indicating that the result was too large to fit in the destination. 
            When set, it indicates that the result of an operation is too large or too small to fit in the destination operand. 


==========================================================================================================================================================
    
    JE/JZ. if ZF is set. [was the result of the operation that last modified FLAGS == 0]

    JNE/JNZ. if ZF is NOT set. [was the result of the operation that last modified FLAGS == 0]
   
    -----------
    JCCS 
    -----------
        ON SIGNED DATA
        -----------------------------------------------------------------
        JG/JNLE [JMP IF GREATER || JMP IF NOT LESS THAN OR EQUAL] 
            CHECKS OF, SF, ZF. 
        
        JGE/JNL [JMP IF GREATER THAN OR EQUAL || JUMP IF NOT LESS THAN]
            CHECKS OF, SF

        JL/JNGE [JMP IF LESS THAN || JMP IF NOT GREATER THAN OR EQUAL TO]
            CHECKS OF, SF
        
        JLE/JNG [JMP IF LESS THAN OR EQUAL || JMP IF NOT GREATER THAN]
            CHECKS OF, SF, ZF

        ------------------------------------------------------------------

        ON UNSIGNED DATA
        ------------------------------------------------------------------
        JA/JNBE [JMP IF ABOVE || JMP IF NOT BELOW OR EQUAL]
            CHECKS ZF.
        
        JAE/JNB [JMP IF ABOVE OR EQUAL || JMP IF NOT BELOW]
            CHECKS CF.

        JB/JNAE [JMP IF BELOW || JMP IF NOT ABOVE OR EQUAL]
            CHECKS CF.
        
        JBE/JNA [JMP IF BELOW OR EQUAL || JMP IF NOT ABOVE]
            CHECKS AF, CF.


    jccs
    
        ja = 0
        jb = 0
        jc = 0
        je = 0
        jg = 0
        jl = 0
        jle = 0
        jo = 0
        js = 0
        jp = 0
        jz = 0
        jnae = 0
        jne = 0
        jnb = 0
        jnz = 0
        jnge = 0
        jnc = 0
        jnbe = 0
        jnl = 0
        jnle = 0
        jpe = 0
        call = 0
        ret = 0
        jmp = 0
        
        
        jae = 0
        jnp = 0
        
        jns = 0
        jno = 0
        
        jbe = 0
        
        jge = 0
        jna = 0
    
        add
        sub
        and
        or
        xor
        not
        cmp
        test
    
    
'''