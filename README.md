# x64dbg-vmp-trace
## this is a plugin for a neat tool you can get here: https://github.com/teemu-l/execution-trace-viewer
unorthodox approach to analyze a trace, but this helped me get comfy with x64 instructions overall (excluding sse/avx/etc lol), cleared up A LOT of misconceptions I had regarding VMP, and helped me not be as spooked as before about trying to use complex libs

## why unorthodox?

everything is done w/ regex. i basically reimplemented all the properties/effects of the mnemonics and registers required to evaluate instructions in their non-byte (lol?) assembly form (eg: mov rax, rsi) to remove junk code and useless chained jumps. 

## WHAT DOES THIS DO? (see pic)

  - makes it easier to get a glimpse of what VMP does

![IMAGE](https://i.gyazo.com/0950b12337e1acb05fce9d9603eb6d68.png)

1. instructions are split into **unique blocks** (essentially basic blocks except jccs aren't used to determine the end of a block [just for this pass]) and assigned IDs 
2. unneeded direct jumps are removed and sequential blocks are merged into actual textbook definition basic blocks.
3. each block is processed and instructions that don't have an impact on the final result (aka dead code) are removed.
## Example output
![vmp1](https://github.com/mibho/x64dbg-vmp-trace/assets/86342821/d588655d-9c76-437a-a649-8f991e3725b7)

## files
* dcr.py: 'dead code remover' logic.   
* fx64_ef_parser: parser that identifies the operator with its operands (if applicable) from an instruction
* VMP_Execution_filter: main part that organizes data into their appropriate structures and deals with the logic for analysis.
* fx64_operands: general purpose registers, segment, and flags. Anything sse/avx is ignored.
* fx64_operators: cheeky implementation of overall effects a mnemonic has on flags/operands 
* fx64_patterns: bunch of regex patterns to identify mnemonics and registers


---------------------------------------------------------------------



09/01/23 - description/context update

07/17/23 - first log [original wip w/ no cleaning; keep for future reflection LOL]
