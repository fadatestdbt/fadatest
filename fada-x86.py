#!/usr/bin/python3

import re
import os
import sys
import random

class insn_asm:
    def __init__(self, str_line):
        self.opcode = ''
        self.oplist = []
        str_line = str_line.strip()
        self.addr = int(str_line.split(':')[0], 16)
        self.is_mem = False
        self.mem_base = ''
        self.mem_base_fake = '%r15'
        self.mem_offset = 0
        #str_tmp = str_line.split(':')[1].split("  ")
        if '%fs' in str_line:
            str_tmp = str_line.replace('%fs:', '%fsx').split(':')[1]
        elif '%cs' in str_line:
            str_tmp = str_line.replace('%cs:', '%fsx').split(':')[1]
        else:
            str_tmp = str_line.split(':')[1]
        if ('xmm' in str_tmp) and ('(' in str_tmp):
            tmp_list = str_tmp.split()
            for i in range(len(tmp_list)):
                if ('0x' in tmp_list[i]) and ('(' in tmp_list[i]):
                    ofs = tmp_list[i].split('(')[0]
                    ofs_rep = ofs[:-1] + '0'
                    str_tmp = str_tmp.replace(ofs, ofs_rep)

        if len(str_tmp.split()[0]) == 2:
            self.arch = 'x86'
            str_tmp = re.sub('  +', ' x ', str_tmp)
            #'x 66 0f 6c c1 x punpcklqdq %xmm1, %xmm0'
            str_tmp = re.split(' x |, ', str_tmp)
            self.encoding = str_tmp[1]
            instr_tmp = ' '.join(str_tmp[2:]).split()
            element_list = []
            join_flag = False
            for item in instr_tmp:
                if not join_flag:
                    element_list.append(item)
                    if ('(' in item) and (')' not in item):
                        join_flag = True
                else:
                    element_list[-1] = element_list[-1] + ', ' + item
                    if ')' in item:
                        join_flag = False
            for item in element_list:
                if ('%' in item) or ('$' in item) or ('0x' in item):
                    self.oplist.append(item)
                else:
                    self.opcode = self.opcode + ' ' + item
            for i in range(len(self.oplist)):
                self.oplist[i] = self.oplist[i].replace('-', '')
                self.oplist[i] = self.oplist[i].replace('rsp', 'r12')
                self.oplist[i] = self.oplist[i].replace('esp', 'r12d')
                self.oplist[i] = self.oplist[i].replace('rip', 'r13')
                self.oplist[i] = self.oplist[i].replace('eip', 'r13d')
                self.oplist[i] = self.oplist[i].replace('rbp', 'r14')
                self.oplist[i] = self.oplist[i].replace('ebp', 'r14d')
                self.oplist[i] = self.oplist[i].replace('bpl', 'r14b')
                self.oplist[i] = self.oplist[i].replace('bp', 'r14w')
                #reserve %r15 for memory base
                self.oplist[i] = self.oplist[i].replace('r15', 'r11')
                #reserve %r10 for loop control
                self.oplist[i] = self.oplist[i].replace('r10', 'r12')
                #reserve %xmm7 for keep single input
                #self.oplist[i] = self.oplist[i].replace('xmm7', 'xmm2')
                #reserve %xmm6 for keep double input
                #self.oplist[i] = self.oplist[i].replace('xmm6', 'xmm3')
                if('%fsx' in self.oplist[i]):
                    self.oplist[i] = '0x35(%r12)'

        else:
            self.arch = 'arm'
            str_tmp = str_line.split(':')[1].split()
            self.encoding = str_tmp[0]
            if len(str_tmp) > 1:
                self.opcode = str_tmp[1]
            if len(str_tmp) > 2:
                self.oplist = str_tmp[2].split(',')
    def dump(self):
        #print("arch: %s" % self.arch)
        #print("%#x" % self.addr),
        #print("%s" % self.encoding),
        print('Memory access: '),
        print(self.is_mem)
        if self.is_mem:
            print('base: %s, offset: %#x' %(self.mem_base, self.mem_offset))
        if self.opcode:
            print("%s" % self.opcode),
        else:
            print("NO opcode!")
            return
        if self.oplist:
            #print("oplist: "),
            print(self.oplist)
        else:
            print('')

class basic_block:
    single_insn_list = ( \
            'sqrtss', 'addss', 'subss', 'mulss', 'divss')
    double_insn_list = ( \
            'sqrtsd', 'addsd', 'mulsd', 'subsd', 'divsd')

    def __init__(self, pc):
        self.in_insn_list = []
        self.reg_set = set()
        self.mem_reg_set = set()
        self.mem_size = {}
        #raw data of hotness of each thread
        self.hotness_raw = []
        #output hotness adjusted with scaling factors
        self.hotness = []
        #sum of each thread group
        self.hotness_tg = []
        #total exec of this block
        self.total_exec = 0
        #Basic Block Type for thread workload assignment
        self.bbt_global_shared = True
        self.bbt_thread_group_shared = []
        self.bbt_thread_exclusive = []
        self.pc = pc
        self.n_thread = 0
        self.block_num = []
        self.offset_step = 1024
        self.length = 0
        self.bb_instrumented = False
        self.asm_instrumented = False
        self.replace_mark_block_num = 'RMBN'
        self.replace_mark_cur_tid= 'RMTID'
        self.frame_only = False
        self.use_unified_mem = True
        self.use_asm_loop = True
        self.has_single_insn = False
        self.has_double_insn = False
        self.has_branch = False

    def bb_instrument(self):
        if self.bb_instrumented:
            return
        self.bb_instrumented = True
        #self.length = len(self.in_insn_list)
        for i in reversed(range(len(self.in_insn_list))):
            #move non-zero value to div instructions
            if 'div'  in self.in_insn_list[i].opcode:
                if self.in_insn_list[i].is_mem:
                    continue
                op_tmp = self.in_insn_list[i].oplist[0]
                fake_insn = \
                        '0x4000a60c2c:  ba 01 00 00 00           movq     $0x35, %rdx'
                insn_set_z = insn_asm(fake_insn)
                self.in_insn_list.insert(i, insn_set_z)
            #remove data
            elif '.byte' in self.in_insn_list[i].opcode:
                self.in_insn_list.pop(i)

    def fini_bb(self, thread_group):
        self.total_exec = sum(self.hotness_raw)
        self.hotness_tg = [0]*len(thread_group)
        self.n_thread = len(self.hotness_raw)
        #self.length = len(self.in_insn_list)

        #Basic Block Type
        for i in range(len(thread_group)):
            for jj in thread_group[i]:
                self.hotness_tg[i] += \
                        self.hotness_raw[jj]
        for item in self.hotness_raw:
            if item == 0:
                self.bbt_global_shared = False
                break
        for item in thread_group:
            thread_shared = True
            for jtem in item:
                if self.hotness_raw[jtem] == 0:
                    thread_shared = False
                    continue
            if thread_shared:
                self.bbt_thread_group_shared.append(item)
            else:
                for jtem in item:
                    if self.hotness_raw[jtem] != 0: 
                        self.bbt_thread_exclusive.append(jtem)
        for i in reversed(range(len(self.in_insn_list))):
            #scan floating point instructions
            if self.in_insn_list[i].opcode.strip() in basic_block.single_insn_list:
                self.has_single_insn = True
            elif self.in_insn_list[i].opcode.strip() in basic_block.double_insn_list:
                self.has_double_insn = True
            #scan memory access
            if 'lea' not in self.in_insn_list[i].opcode:
                for item in self.in_insn_list[i].oplist:
                    if '(' in item:
                        #if 'mov' not in self.in_insn_list[i].opcode:
                        #    print('######')
                        #    print(self.in_insn_list[i].opcode)
                        #    print(self.in_insn_list[i].oplist)
                        reg_tmp = re.findall(r'[(](.*?)[)]', item) 
#                        self.in_insn_list[i].mem_base = reg_tmp[0].split()[0].replace(',', '')
                        for mem_opnd in reg_tmp[0].split():
                            if '%' in mem_opnd:
                                self.in_insn_list[i].mem_base = mem_opnd.replace(',', '')
                        #print(self.in_insn_list[i].opcode)
                        #print(self.in_insn_list[i].oplist)
                        if len(item.split('(')[0]) > 0:
                            self.in_insn_list[i].mem_offset = \
                                    int(item.split('(')[0].replace('*', ''), 16)
                        else:
                            self.in_insn_list[i].mem_offset = 0
                        self.mem_reg_set.add(self.in_insn_list[i].mem_base)
                        mem_base_tmp = self.in_insn_list[i].mem_base
                        if self.mem_size.get(mem_base_tmp):
                            self.mem_size[mem_base_tmp] = max(self.mem_size[mem_base_tmp], self.in_insn_list[i].mem_offset + 1)
                        else:
                            self.mem_size[mem_base_tmp] = self.in_insn_list[i].mem_offset + 1
                        self.in_insn_list[i].is_mem = True
        self.mem_rw = bool(len(self.mem_size.values()))
        self.bb_instrument()


    def gen_output(self):
        print('\t\t:')

    def gen_input(self):
        print('\t\t:', end = '')
        str_tmp = ''
        if self.mem_rw and self.use_unified_mem:
            str_tmp = '[input_mem_base] "m" (ptr_mem_base)'
        if self.has_single_insn:
            if len(str_tmp) > 0:
                str_tmp += ','
            str_tmp += '[input_single_val] "m" (ptr_single_float)'
        if self.has_double_insn:
            if len(str_tmp) > 0:
                str_tmp += ','
            str_tmp += '[input_double_val] "m" (ptr_double_float)'
        print(str_tmp)
        print('')
        return

        is_first = True
        for (reg, mem_size) in self.mem_size.items():
            reg = reg.replace('%', '')
            ######## DO NOT SUPPORT VECTORS ##########
            #if '.' in item.key or 'v' in item.key:
            #    continue
            if is_first:
                sym = ''
                is_first = False
            else:
                sym = ','
            print(sym,end='')
            print('[input_%s_%d] "m" (ptr_%s_%d_in)' % (reg, self.block_num[gen_code.cur_tid], reg, self.block_num[gen_code.cur_tid]), end='')
        print('')

    def gen_clobbers(self):                
        dist_set = set([])
        print('\t\t',end='')
        #print('gen_clobbers')
        is_colon = True
        for reg in self.reg_set:
            reg = reg.replace('%', '')
            if bool(re.search(r'\d', reg)):
                reg = reg.replace('b', '')
                reg = reg.replace('d', '')
                reg = reg.replace('w', '')
            ######## DO NOT SUPPORT VECTORS ##########
            #if not (('x' in item) or ('w' in item)):
            #    continue
            #if '#' in item:
            #    continue
            if is_colon:
                sym = ':'
                is_colon = False
            else:
                sym = ','
            print(sym,end='')
            print('"%s"' % reg, end='')
        print('')

    def gen_asm_tail(self):
        self.gen_output()
        self.gen_input()
        self.gen_clobbers()

    def reg_set_add(self, in_reg_set, in_reg):
        if in_reg_set == None:
            reg_set = self.reg_set
        else:
            reg_set = in_reg_set
        reg_a = ('%rax', '%eax', '%ax', '%al')
        reg_b = ('%rbx', '%ebx', '%bx', '%bl')
        reg_c = ('%rcx', '%ecx', '%cx', '%cl')
        reg_d = ('%rdx', '%edx', '%dx', '%dl')
        reg_S = ('%rsi', '%esi', '%si')
        reg_D = ('%rdi', '%edi', '%si')

        if in_reg[-1] == 'b' or in_reg[-1] == 'd':
            reg_set.add(in_reg[:-1])
        elif in_reg in reg_a:
            reg_set.add('rax')
        elif in_reg in reg_b:
            reg_set.add('rbx')
        elif in_reg in reg_c:
            reg_set.add('rcx')
        elif in_reg in reg_d:
            reg_set.add('rdx')
        elif in_reg in reg_S:
            reg_set.add('rsi')
        elif in_reg in reg_D:
            reg_set.add('rdi')
        else:
            reg_set.add(in_reg)

    def reg_set_check(self, in_reg_set, in_reg):
        if in_reg_set == None:
            reg_set = self.reg_set
        else:
            reg_set = in_reg_set
        reg_a = ('%rax', '%eax', '%ax', '%al')
        reg_b = ('%rbx', '%ebx', '%bx', '%bl')
        reg_c = ('%rcx', '%ecx', '%cx', '%cl')
        reg_d = ('%rdx', '%edx', '%dx', '%dl')
        reg_S = ('%rsi', '%esi', '%si')
        reg_D = ('%rdi', '%edi', '%si')

        if in_reg[-1] == 'b' or in_reg[-1] == 'd':
            return (in_reg[:-1] in reg_set)
        elif in_reg in reg_a:
            return ('rax' in reg_set)
        elif in_reg in reg_b:
            return ('rbx' in reg_set)
        elif in_reg in reg_c:
            return ('rcx' in reg_set)
        elif in_reg in reg_d:
            return ('rdx' in reg_set)
        elif in_reg in reg_S:
            return ('rsi' in reg_set)
        elif in_reg in reg_D:
            return ('rdi' in reg_set)
        else:
            return (in_reg in reg_set)

    def get_reg_alians(self, in_reg):
        if not in_reg:
            return in_reg
        reg_a = ('%rax', '%eax', '%ax', '%al')
        reg_b = ('%rbx', '%ebx', '%bx', '%bl')
        reg_c = ('%rcx', '%ecx', '%cx', '%cl')
        reg_d = ('%rdx', '%edx', '%dx', '%dl')
        reg_S = ('%rsi', '%esi', '%si')
        reg_D = ('%rdi', '%edi', '%si')
        if in_reg[-1] == 'b' or in_reg[-1] == 'd':
            ret = in_reg[:-1]
        elif in_reg in reg_a:
            ret = '%rax'
        elif in_reg in reg_b:
            ret = '%rbx'
        elif in_reg in reg_c:
            ret = '%rcx'
        elif in_reg in reg_d:
            ret = '%rdx'
        elif in_reg in reg_S:
            ret = '%rsi'
        elif in_reg in reg_D:
            ret = '%rdi'
        else:
            ret = in_reg
        return ret



    def instrument_asm(self):
        if self.asm_instrumented:
            return
        self.asm_instrumented = True
        touched_reg = {}
        fake_insn = '0x4000a2491d:  48 8b 75 a8              movq     -0x58(%rbp), %rsi'
        for i in range(len(self.in_insn_list)):
            cur_insn = self.in_insn_list[i]
            #branch instructions, not suported
            if ('call' in cur_insn.opcode) \
                    or ('hlt' in cur_insn.opcode) \
                    or ('push' in cur_insn.opcode) \
                    or ('pop' in cur_insn.opcode) \
                    or ('cli' in cur_insn.opcode) \
                    or ('cltq' in cur_insn.opcode) \
                    or ('div' in cur_insn.opcode) \
                    or ('leave' in cur_insn.opcode) \
                    or ('rep movsq' in cur_insn.opcode) \
                    or ('cvtsi2ssl' in cur_insn.opcode) \
                    or ('loopne' in cur_insn.opcode) \
                    or ('cpuid' in cur_insn.opcode) \
                    or ('rdtsc' in cur_insn.opcode) \
                    or ('fxrstor' in cur_insn.opcode) \
                    or ('enter' in cur_insn.opcode) \
                    or ('repz' in cur_insn.opcode) \
                    or ('repe' in cur_insn.opcode) \
                    or ('lock' in cur_insn.opcode) \
                    or ('cqto' in cur_insn.opcode) \
                    or ('cltd' in cur_insn.opcode) \
                    or ('movb' in cur_insn.opcode) \
                    or ('repne scasb' in cur_insn.opcode) \
                    or ('ret' in cur_insn.opcode):
                cur_insn.opcode = ' nop\\n\\t'
                cur_insn.oplist.clear()
                continue

            if ('rep stosq' in cur_insn.opcode):
                cur_insn.opcode = ' movq'

            if ('xchgl' in cur_insn.opcode):
                cur_insn.opcode = ' movl'


            if cur_insn.is_mem:
                to_insert = False
                for k in range(len(cur_insn.oplist)):
                    #case memory access
                    if cur_insn.mem_base in cur_insn.oplist[k] \
                            and '(' in cur_insn.oplist[k]:
                        if not self.get_reg_alians(cur_insn.mem_base) in touched_reg.keys():
                            # insert prep mem instn
                            to_insert = True
                        elif touched_reg[self.get_reg_alians(cur_insn.mem_base)]:
                            #print('RE-insert')
                            #print(cur_insn.opcode, cur_insn.oplist)
                            to_insert = True
                            #insert prep mem instn
                        #replace
                        offset_tmp = cur_insn.oplist[k].split('(')[0]
                        if self.use_unified_mem:
                            cur_insn.oplist[k] = offset_tmp + '(' \
                                    + cur_insn.mem_base_fake + ')'
                        else:
                            cur_insn.oplist[k] = offset_tmp + '(' \
                                    + cur_insn.mem_base + ')'
                if to_insert and (not self.use_unified_mem):
                    cur_insn.opcode = cur_insn.opcode + 'INS_MEM'
                    if (cur_insn.mem_base in cur_insn.oplist[-1]) \
                            and (not '(' in cur_insn.oplist[-1]):
                        touched_reg[self.get_reg_alians(cur_insn.mem_base)] = True
                    else:
                        touched_reg[self.get_reg_alians(cur_insn.mem_base)] = False

            #mark as touched if mem_base is used as dist reg
            if len(cur_insn.oplist) > 0:
                if (not '(' in cur_insn.oplist[-1]) and \
                        (self.get_reg_alians(cur_insn.oplist[-1]) \
                        in touched_reg.keys()):
                    #print('Touched:')
                    #print(cur_insn.oplist[-1])
                    touched_reg[self.get_reg_alians(cur_insn.oplist[-1])] = True

        for i in reversed(range(len(self.in_insn_list))):
            cur_insn = self.in_insn_list[i]
            if len(cur_insn.oplist) > 0:
                if ('%' in cur_insn.oplist[-1]) and \
                        (not '(' in cur_insn.oplist[-1]):
                    self.reg_set_add(None, cur_insn.oplist[-1].replace('*', ''))
                if ('0x' in cur_insn.oplist[-1]) and \
                        (not '(' in cur_insn.oplist[-1]):
                    cur_insn.oplist[-1] = '%r12'

            if cur_insn.opcode.strip() in basic_block.single_insn_list:

                '''
                #for supporting floating point instructions
                fake_insn = '0x4000a2491d:  48 8b 75 a8              movq     -0x58(%rbp), %rsi'
                for op_i in range(len(cur_insn.oplist)):
                    insn_tmp = insn_asm(fake_insn)
                    insn_tmp.opcode = ' movss'
                    insn_tmp.oplist = ['%%xmm7', cur_insn.oplist[op_i].replace('%', '%%')]
                    #self.in_insn_list.insert(i, insn_tmp)
                insn_tmp = insn_asm(fake_insn)
                insn_tmp.opcode = ' movss'
                insn_tmp.oplist = ['%[input_single_val]', '%%xmm7']
                self.in_insn_list.insert(i, insn_tmp)

            if cur_insn.opcode.strip() in basic_block.double_insn_list:
                fake_insn = '0x4000a2491d:  48 8b 75 a8              movq     -0x58(%rbp), %rsi'
                for op_i in range(len(cur_insn.oplist)):
                    insn_tmp = insn_asm(fake_insn)
                    insn_tmp.opcode = ' movss'
                    insn_tmp.oplist = ['%%xmm6', cur_insn.oplist[op_i].replace('%', '%%')]
                    #self.in_insn_list.insert(i, insn_tmp)
                insn_tmp = insn_asm(fake_insn)
                insn_tmp.opcode = ' movss'
                insn_tmp.oplist = ['%[input_double_val]', '%%xmm6']
                #self.in_insn_list.insert(i, insn_tmp)
                '''

            if 'INS_MEM' in cur_insn.opcode:
                cur_insn.opcode = cur_insn.opcode.replace('INS_MEM', '')
                insn_tmp = insn_asm(fake_insn)
                op_replace = '%%[input_%s_%s]' % (cur_insn.mem_base.replace('%', ''), self.replace_mark_block_num)
                reg_replace = cur_insn.mem_base.replace('%', '%%')
                insn_tmp.oplist = [op_replace, reg_replace]
                self.in_insn_list.insert(i, insn_tmp)
                self.reg_set_add(None, cur_insn.mem_base)

            if 'j' in cur_insn.opcode:
                cur_insn.oplist = ['jmp_hit_%s_%s' % (self.replace_mark_block_num, self.replace_mark_cur_tid)]
                if 'jmpq' in cur_insn.opcode.strip():
                    cur_insn.opcode = ' jne'
                self.has_branch = True

            for j in range(len(cur_insn.oplist)):
                if not 'input' in cur_insn.oplist[j]:
                    cur_insn.oplist[j] = \
                            cur_insn.oplist[j].replace('%', '%%')
                    if ('0x' in cur_insn.oplist[j]) \
                            and (not '(' in cur_insn.oplist[j]) \
                            and (not '$'  in cur_insn.oplist[j]):
                        cur_insn.oplist[j] = '$' + cur_insn.oplist[j]


            #for j in range(len(cur_insn.oplist)):
            #    cur_insn.oplist[j] = cur_insn.oplist[j].replace('%', '%%')

#                        fake_insn = '0x4000a2491d:  48 8b 75 a8              movq     -0x58(%rbp), %rsi'
#                        insn_tmp = insn_asm(fake_insn)
#                        op_replace = '%[input_%s_%d]' % (self.mem_base.replace('%', ''), self.block_num)
#                        reg_replace = self.mem_base.replace('%', '%%')
#                        insn_tmp.oplist = [op_replace, reg_replace]
#                        self.in_insn_list.insert(i, insn_tmp)
#                        touched_reg[self.mem_base] = False
#


    def print_asm(self, asm_loop_scale):
        if self.frame_only:
            asm_str = 'nop'
            print('\t\t"%s\\n\\t"' % (asm_str))
            return
        if self.use_unified_mem and self.mem_rw:
            asm_str = ' movq %[input_mem_base], %%r15'
            print('\t\t"%s\\n\\t"' % (asm_str))
        if self.use_asm_loop:
            asm_str = ' movq $%d, %%%%r10' % (int(self.hotness_raw[gen_code.cur_tid] * asm_loop_scale + 1))
            print('\t\t"%s\\n\\t"' % (asm_str))
            asm_str = ' loop_%d_%d:' % (self.block_num[gen_code.cur_tid], gen_code.cur_tid)
            print('\t\t"%s\\n\\t"' % (asm_str))
        for repeat in range(gen_code.repeat_asm_block):
            for asm in self.in_insn_list:
                asm_str = asm.opcode
                for i in range(len(asm.oplist)):
                    if i == 0:
                        split_sym = ' '
                    else:
                        split_sym = ', '
                    asm_str = asm_str + split_sym \
                            + asm.oplist[i].replace(self.replace_mark_block_num, str(self.block_num[gen_code.cur_tid]))
                    asm_str = asm_str.replace(self.replace_mark_cur_tid, str(gen_code.cur_tid))
                print('\t\t"%s\\n\\t"' % (asm_str))

        if self.has_branch:
                asm_str = ' test %%r15, %%r15'
                print('\t\t"%s\\n\\t"' % (asm_str))
                asm_str = ' jmp_hit_%d_%d:' % (self.block_num[gen_code.cur_tid], gen_code.cur_tid)
                print('\t\t"%s\\n\\t"' % (asm_str))

        if self.use_asm_loop:
            asm_str = ' dec %%r10'
            print('\t\t"%s\\n\\t"' % (asm_str))
            asm_str = ' test %%r10, %%r10'
            print('\t\t"%s\\n\\t"' % (asm_str))
            asm_str = ' jnz loop_%d_%d' % (self.block_num[gen_code.cur_tid], gen_code.cur_tid)
            print('\t\t"%s\\n\\t"' % (asm_str))
        
            #print('[input_%s_%d] "m" (ptr_%s_%d_in)' % (reg, self.block_num[gen_code.cur_tid], reg, self.block_num[gen_code.cur_tid]), end='')

    def gen_prep_mem(self):
        if self.use_unified_mem:
            return
        malloc_str_list=[]
        for (reg, mem_size) in self.mem_size.items():
            reg = reg.replace('%', '')

            ######## DO NOT SUPPORT VECTORS ##########
            #if '.' in item.key or 'v' in item.key:
            #    continue
        #    ret_list.append('\t//Block_num: %d' % self.block_num)

            malloc_str = ('\tlong *ptr_%s_%d = malloc(sizeof(long) * %d);\n' % (reg, self.block_num[gen_code.cur_tid], mem_size + 64)) \
                    + ('\tlong *ptr_%s_%d_in = alignment16(ptr_%s_%d);\n' % (reg, self.block_num[gen_code.cur_tid], reg, self.block_num[gen_code.cur_tid])) \
                    + ('\tassert(ptr_%s_%d_in);\n' % (reg, self.block_num[gen_code.cur_tid]))

#                    + ('\tfor(int i = 0; i < %d; i++)\n\t{\n\t\tptr_%s_%d[i] = rand();\n\t}\n' % (item.value, item.key, self.block_num))

            malloc_str_list.append(malloc_str)

#            print('\tlong *ptr_%s_%d = malloc(sizeof(long) * %d);' % (item.key, self.block_num, item.value))
#            print('\tfor(int i = 0; i < %d; i++)\n\t{\n\t\tptr_%s_%d[i] = rand();\n\t}' % (item.value, item.key, self.block_num))
#        print('')

        gen_code.add_gen_malloc(malloc_str_list)

    def gen_free_mem(self):
        if self.use_unified_mem:
            return
        free_str_list=[]
        for (reg, mem_size) in self.mem_size.items():
            reg = reg.replace('%', '')
            ######## DO NOT SUPPORT VECTORS ##########
            #if '.' in item.key or 'v' in item.key:
            #    continue
        #    ret_list.append('\t//Block_num: %d' % self.block_num)
            free_str_list.append('\tfree(ptr_%s_%d);' % (reg, self.block_num[gen_code.cur_tid]))
        gen_code.add_gen_free(free_str_list)
#            print('\tfree(ptr_%s_%d);' % (item.key, self.block_num))

    def gen_inline_asm(self, asm_loop_scale):
#        print('\tgettimeofday(&tv_begin, NULL);')
        #print('\tfor(long i = 0;i < %d;i++)\n\t{' % self.hotness_raw[tid])
        if not self.use_asm_loop:
            print('\tfor(long i = 0;i < %d;i++)\n\t{' % (self.hotness_raw[gen_code.cur_tid] * asm_loop_scale + 1))
        print('\tasm volatile(')
        self.instrument_asm()
        self.print_asm(asm_loop_scale)
        self.gen_asm_tail()
        print('\t);')
        '''
        for (reg, mem_size) in self.mem_size.items():
            reg = reg.replace('%', '')
            ######## DO NOT SUPPORT VECTORS ##########
            #filter not supported operand
            if ('vvvv' not in reg) and ('xxxx' not in reg):
                print('\t\t}{static long long offset_%s_%d = 0;' % (reg, self.block_num))
                print('\t\toffset_%s_%d = (offset_%s_%d + %d) %% (%d - 8192);' % (reg, self.block_num, reg, self.block_num, self.offset_step, mem_size))
                print('\t\tptr_%s_%d_in = ptr_%s_%d + offset_%s_%d;' % (reg, self.block_num, reg, self.block_num, reg, self.block_num))
        '''
        if not self.use_asm_loop:
            print('\t}')
#        print('\tgettimeofday(&tv_end, NULL);')
#        print('\ttimersub(&tv_end, &tv_begin, &tv_sub);')
#        print('\ttimeradd(&tv_sum, &tv_sub, &tv_sum);')

    def dump(self):
        print('PC: %#x' % self.pc)
        print('hotness:'),
        print(self.hotness)
        print('hotness_tg:'),
        print(self.hotness_tg)
        print('total_exec:'),
        print(self.total_exec)
        print('global shared:'),
        print(self.bbt_global_shared)
        print('thread group shared:'),
        print(self.bbt_thread_group_shared)
        print('thread exclusive:'),
        print(self.bbt_thread_exclusive)
        print('mem_reg_set: '),
        print(self.mem_reg_set)
        print('mem_size: '),
        print(self.mem_size)
        for item in self.in_insn_list:
            item.dump()

class read_log:
    def __init__(self, hotness_path, asm_path, thread_group):
        self.bb_dict = {}
        self.bb_list = []
        self.thread_group = thread_group
        self.hotness_path = hotness_path
        self.asm_path = asm_path
        self.n_thread = 0
        self.read_hotness_log()
        self.read_asm_log()

    def read_hotness_log(self):
        f = open(self.hotness_path)
        line = f.readline()
        while line:
            if line.startswith('pc = '):
                if '0x' in line:
                    pc = int(line.strip().split('x')[1], 16)
                else:
                    pc = int(line.strip().split()[2], 16)
                if not self.bb_dict.get(pc):
                   # print('[Warning] Redundant hotness record detected: %#x' % pc)
                    cur_bb = basic_block(pc)
                    self.bb_list.append(cur_bb)
                    self.bb_dict[pc] = self.bb_list[-1]
                else:
                    cur_bb = self.bb_dict[pc]
                line = f.readline()
                cur_tid = 0
                while line:
                    if 'tid = ' in line and 'count = ' in line:
                        tmp = line.split()
                        #tid = int(tmp[2])
                        tid = cur_tid
                        cur_tid += 1
                        if 'count2' in line:
                            print('OVERFLOW DETECTED!')
                            exit(1)
                            line = f.readline()
                            continue
                        count = int(tmp[5])
                        if len(cur_bb.hotness_raw) <= tid:
                            cur_bb.hotness_raw.append(count)
                        else:
                            cur_bb.hotness_raw[tid] += count
                        line = f.readline()
                    else:
                        self.n_thread = len(cur_bb.hotness_raw)
                        break
            else:
                line = f.readline()
        f.close()

    def read_asm_log(self):
        f = open(self.asm_path)
        line = f.readline()
        while line:
            if line.startswith('---'):
                cur_bb = None
                line = f.readline()
                if line.startswith('IN'):
                    line = f.readline()
                    pc = None
                    while len(line) > 1:
                        insn_tmp = insn_asm(line)
                        if not pc:
                            pc = insn_tmp.addr
                            if not self.bb_dict.get(pc):
                                break;
                            cur_bb = self.bb_dict[pc]
                            if len(cur_bb.in_insn_list) > 0:
                                break
                        cur_bb.in_insn_list.append(insn_tmp)
                        cur_bb.length += 1
                        line = f.readline()
                    if cur_bb:
                        #cur_bb.block_num = bb_count
                        cur_bb.fini_bb(self.thread_group)
                        del cur_bb
                    line = f.readline()
            else:
                line = f.readline()
        f.close()

    def take_hot_value(self, elem):
        return elem[1]

    def sort_hotness(self):
        full_list = []
        self.n_thread = len(self.bb_list[0].hotness)
        for i in range(self.n_thread):
            full_list.append([])
            for item in self.bb_list:
                full_list[i].append([item.pc, item.hotness_raw[i]])

        for ii in range(self.n_thread):
            full_list[ii].sort(key = self.take_hot_value, reverse = True)
            return full_list
            print('Thread %d: ' % ii)
            for j in range(len(full_list[ii])):
                print('PC: %#x, count = %d' % (full_list[ii][j][0], full_list[ii][j][1]))

    def dump(self):
        for item in self.bb_list:
            print('\n---------------------------------')
            item.dump()

class gen_code:
    gen_malloc = []
    gen_free = []
    cur_tid = 0
    repeat_asm_block = 10
    exclude_blk = (999999,)
#    exclude_blk = (1877,)
    #exclude_blk = (1931,)#641
    def __init__(self):
        #ab represents asm block, i.e., basic block
        self.ab_loaded = False
        self.ab_list = []
        self.exclude_blk = gen_code.exclude_blk
        self.start_blk = 0
        self.count_limit = 50000
        self.print_flag = False
        #number of blocks in a single c file:
        self.split_size = 3
        self.fixed_hotness = 1
        self.full_loop = 1
        self.asm_loop_scale = 1/float(10000)
        self.offset_step = 1024
        self.use_mt = True
        self.frame_only = False
        self.print_mem_prep = False
        self.thread_mem_size = []
        self.max_mem_size = 0
        self.bench_name = ''

    @classmethod
    def add_gen_malloc(self, gen_malloc_list):
        gen_code.gen_malloc[gen_code.cur_tid] = gen_code.gen_malloc[gen_code.cur_tid] + gen_malloc_list
    
    @classmethod
    def add_gen_free(self, gen_free_list):
        gen_code.gen_free[gen_code.cur_tid] = gen_code.gen_free[gen_code.cur_tid] + gen_free_list

    def take_hot_value(self, elem):
        return elem[1]

    #load asm file, asm orgnized as blocks seperated by empty lines
    #There must be at least one empty line at the end of asm file
    def load_asm(self, hotness_path, asm_path, thread_group):
        self.rl = read_log(hotness_path, asm_path, thread_group)
        self.n_thread = len(self.rl.bb_list[0].hotness_raw)

        for i in range(self.n_thread):
            self.ab_list.append([])
            self.thread_mem_size.append(0)
            gen_code.gen_malloc.append([])
            gen_code.gen_free.append([])
            for item in self.rl.bb_list:
                self.ab_list[i].append([item.pc, item.hotness_raw[i]])
                if (len(item.mem_size.values())) > 0:
                    self.thread_mem_size[i] = max(self.thread_mem_size[i], max(item.mem_size.values()))
        self.max_mem_size = max(self.thread_mem_size)

        for ii in range(self.n_thread):
            self.ab_list[ii].sort(key = self.take_hot_value, reverse = True)
        for iii in range(self.n_thread):
            #print('Thread %d: ' % iii)
            for j in range(len(self.ab_list[iii])):
                gen_code.cur_tid = iii
                pc_tmp = self.ab_list[iii][j][0]
                cur_bb = self.rl.bb_dict[pc_tmp]
                cur_bb.block_num.append(j)
                cur_bb.gen_prep_mem()
                cur_bb.gen_free_mem()
                cur_bb.frame_only = self.frame_only
                #print('%d:\tPC: %#x, count = %d' % (j, self.ab_list[iii][j][0], self.ab_list[iii][j][1]))
        #exit(0)

    def gen_c_file_head(self):
        print('#include <stdio.h>\n#include <stdlib.h>\n#include "assert.h"\n#include <sys/time.h>\n\n#define alignment16(a) (void*)(((unsigned long long)a+0x0F)&(~0x0F)) \nlong *ptr_mem_base;\nfloat *ptr_single_float;\ndouble *ptr_double_float;')

    def gen_func_main(self):
        print('int main(void)\n{')
        print('\t//srand((unsigned)time(NULL));\n\tstruct timeval tv_begin, tv_end, tv_sum, tv_sub;')
        print('\tlong *tmp_mem_base = malloc(%d * sizeof(long));' % (self.max_mem_size + 32))
        print('\tptr_mem_base = alignment16(tmp_mem_base);')
        print('\tptr_single_float = malloc(sizeof(float));')
        print('\t*ptr_single_float = 314159.2653589;')
        print('\tptr_double_float = malloc(sizeof(double));')
        print('\t*ptr_double_float = 271828.1828459;')
        print('\tint percent = 100;')

        if self.use_mt:
            print('\tpthread_t tid[%d];' % (self.n_thread - 1))
            print('\ttv_sum.tv_sec = 0;\n\ttv_sum.tv_usec = 0;')
            print('\tgettimeofday(&tv_begin, NULL);')

            if self.bench_name == 'bodytrack':
                for i in range(1, self.n_thread):
                    print('\tpthread_create(&(tid[%d]), NULL, (void*)run_thread_%d, &percent);' % (i - 1, i))
                print('\trun_thread_0(&percent);')
                for i in range(self.n_thread - 1):
                    print('\tpthread_join(tid[%d], NULL);' % (i))

            elif self.bench_name == 'streamcluster':
                print('\tint percent_1 = 20;')
                print('\tint percent_2 = 16;')
                print('\trun_thread_0(&percent_1);')
                for i in range(0, 6):
                    for j in range(1, 5):
                        tid_tmp = j + i * 4;
                        print('\tpthread_create(&(tid[%d]), NULL, (void*)run_thread_%d, &percent);' % (tid_tmp - 1, tid_tmp))
                    for j in range(1, 5):
                        index_tmp = j + i * 4 - 1;
                        print('\tpthread_join(tid[%d], NULL);' % (index_tmp))
                    if i < 5:
                        print('\trun_thread_0(&percent_2);')
            else:
                print('\tint percent_1 = 80;')
                print('\tint percent_2 = 20;')
                print('\trun_thread_0(&percent_1);')
                for i in range(1, self.n_thread):
                    print('\tpthread_create(&(tid[%d]), NULL, (void*)run_thread_%d, &percent);' % (i - 1, i))
                for i in range(self.n_thread - 1):
                    print('\tpthread_join(tid[%d], NULL);' % (i))
                print('\trun_thread_0(&percent_2);')

        else:
            for i in range(1, self.n_thread):
                print('\trun_thread_%d(100);' % i);

        print('\tgettimeofday(&tv_end, NULL);')
        print('\ttimersub(&tv_end, &tv_begin, &tv_sub);')
        print('\ttimeradd(&tv_sum, &tv_sub, &tv_sum);')
        print('\tprintf("Finished!\\n");')
        print('\tprintf("Main time:\\n\\ttv_sum.tv_sec = %ld, tv_sum.tv_usec = %ld\\n", tv_sum.tv_sec, tv_sum.tv_usec);')
        print('\tfree(tmp_mem_base);\n')
        print('\treturn 0;\n}')
        print('\n/////////////////// END OF MAIN ///////////////////')

    def gen_func_head(self, tid):
        print('/***** pct(valid value range 1-100) is the percentage of full test ')
        print('           to emulate thread activity    *****/')
        print('int run_thread_%d(int *in_pct)\n{' % tid)
        #print('\t//srand((unsigned)time(NULL));\n\tstruct timeval tv_begin, tv_end, tv_sum, tv_sub;')
        #print('\ttv_sum.tv_sec = 0;\n\ttv_sum.tv_usec = 0;')
        print('\tint pct = *in_pct;')
        print('\tif(pct < 1 || pct >= 100){')
        print('\t\tpct = 100;\n\t}\n')
        if self.print_mem_prep:
            print('\tprintf("Preparing memory for %%d\\n", %d);' % tid)

    def gen_c_file_tail(self):
        #print('\tprintf("Finished!\\n");')
        #print('\tprintf("Total time:\\n\\ttv_sum.tv_sec = %ld, tv_sum.tv_usec = %ld\\n", tv_sum.tv_sec, tv_sum.tv_usec);')
        print('\treturn 0;\n}')
        print('/////////////////// END OF FILE ///////////////////')

    def gen_c_file(self, start, count):
        self.start_blk = start
        self.count_limit = count
        self.gen_c_file_head()
        for i in range(self.n_thread):
            gen_code.cur_tid = i
            self.gen_func_head(i)
            end_of_file = True
            for item in gen_code.gen_malloc[gen_code.cur_tid]:
                blk_num = int(item.split('_')[2].split()[0])
                if blk_num < self.start_blk:
                    continue
                if (blk_num > self.start_blk + self.count_limit - 1):
                    break
                print(item)
            if self.print_mem_prep:
                print('\tprintf("Memory ready for %%d\\n", %d);' % gen_code.cur_tid)
            #print('\tgettimeofday(&tv_begin, NULL);')
            print('for(int full_loop = 0;full_loop * pct / 100 < %d;full_loop++)\n{' % self.full_loop)
            blk_count = 0

        #for ii in range(self.n_thread):
        #    print('Thread %d: ' % ii)
        #    for j in range(len(self.ab_list[ii])):
        #        print('PC: %#x, count = %d' % (self.ab_list[ii][j][0], self.ab_list[ii][j][1]))

            for item in self.ab_list[i]:
                cur_bb = self.rl.bb_dict[item[0]]
                if blk_count < self.start_blk:
                    blk_count += 1
                    continue
            ########## DO NOT SUPPORT 339th block ###########
                if cur_bb.pc in self.exclude_blk:
                    blk_count += 1
                    continue
                if (blk_count > self.start_blk + self.count_limit - 1):
                    end_of_file = False
                    break

                if self.print_flag:
                    print('\tprintf("Block: %d, pc = %#x \\n");' % (blk_count, cur_bb.pc))
                else:
                    print('\t//printf("Block: %d, pc = %#x \\n");' % (blk_count, cur_bb.pc))

                hotness_tmp = cur_bb.hotness_raw[gen_code.cur_tid] 
                print('//hotness = %d' % hotness_tmp)
                if hotness_tmp * self.full_loop * float(self.asm_loop_scale) * gen_code.repeat_asm_block >= gen_code.repeat_asm_block:
                    cur_bb.gen_inline_asm(self.asm_loop_scale)
                blk_count += 1
        #for ii in range(self.n_thread):
        #    print('Thread %d: ' % ii)
        #    for j in range(len(self.ab_list[ii])):
        #        print('PC: %#x, count = %d' % (self.ab_list[ii][j][0], self.ab_list[ii][j][1]))
            print('}////// END OF FULL_LOOP')
            #print('\tgettimeofday(&tv_end, NULL);')
            #print('\ttimersub(&tv_end, &tv_begin, &tv_sub);')
            #print('\ttimeradd(&tv_sum, &tv_sub, &tv_sum);')
            if self.print_mem_prep:
                print('\tprintf("Cleaning memory for %%d\\n", %d);' % gen_code.cur_tid)
            for item in gen_code.gen_free[gen_code.cur_tid]:
                blk_num = int(item.split('_')[2].split(')')[0])
                if blk_num < self.start_blk:
                    continue
                if (blk_num > self.start_blk + self.count_limit - 1):
                    break
                print(item)
            if self.print_mem_prep:
                print('\tprintf("Memory cleaned for %%d\\n", %d);' % gen_code.cur_tid)


            self.gen_c_file_tail()
        self.gen_func_main()
        #if it is the end of file, read cannot be continued, return False, otherwise return True
        return (not end_of_file)

class parsec_app:
    def __init__(self, bench_name):
        log_dir = '../fadatest-data-raw/x86-on-x86-qemu-hotness/'
        pre = 'parsec.'
        sur_hot = '-native-4-hotness.log'
        sur_asm = '-native-4-hotness-in-asm.log'
        self.bench_name = bench_name
        self.hotness_path = log_dir + pre + bench_name + sur_hot
        self.asm_path = log_dir + pre + bench_name + sur_asm
        self.thread_group = {}
        self.exclude_blk = {}
        self.thread_group['blackscholes'] = [[0], [1, 2, 3, 4]]
        '''
        self.exclude_blk['blackscholes'] = (0x4000001a5c, \
                0x4000824c0e, 0x40008164d0, 0x4000811460, \
                0x4000811485, 0x400081149c)
        '''
        self.thread_group['bodytrack'] = [[0], [1, 2, 3, 4], [5]]
        self.thread_group['canneal'] = [[0], [1, 2, 3, 4]]
        self.thread_group['dedup'] = \
                [[0], [1], [2, 3, 4, 5], [6, 7, 8, 9], [10, 11, 12, 13], [14]]
        self.thread_group['ferret'] = \
                [[0], [1], [2, 3, 4, 5], [6, 7, 8, 9], [10, 11, 12, 13], [14, 15, 16, 17], [18]]
        self.thread_group['fluidanimate'] = [[0], [1, 2, 3, 4]]
        self.thread_group['freqmine'] = [[0, 1, 2, 3]]
        '''
        self.exclude_blk['freqmine'] = (0x4000005521, \
                0x40000057f0, 0x4000008460, 0x4000009164, \
                0x4000003f96, 0x4000007030, 0x4000008860, \
                0x4000003c89, 0x4000003c68, 0x4000009278, \
                0x4000009264, 0x4000009267, 0x4000007043, \
                0x4000003809, 0x40000038f4, 0x4000006df4, \
                0x4000b9d640, 0x4000008010, 0x400000663e, \
                0x4000008180, 0x40000033b8, 0x4000b9dfe0, \
                0x400000339c, 0x4000004844, 0x4000006ebd, \
                0x40000046d5, 0x40000036cb, 0x4000007abe, \
                0x4000005566, 0x4000008618, 0x4000008a10, \
                0x4000007a44, 0x400000878b, 0x4000008b7b)
        '''
        self.thread_group['streamcluster'] = [[0], [1, 2, 3, 4], [5, 6, 7, 8]]
        self.thread_group['swaptions'] = [[0], [1, 2, 3, 4]]
        '''
        self.exclude_blk['swaptions'] = (0x4000004c75, )
        '''
        self.thread_group['vips'] = [[0], [1, 2, 3, 4]]

        if not bench_name in self.thread_group.keys():
            print('Invalid applicaion!')
            exit(1)

        self.full_loop = 10
        self.asm_loop_scale = 1/float(500)
        self.frame_only = False
        self.use_mt = True
        self.print_flag = False
        self.print_mem_prep = False
        self.bb_range = (0, 2000)

    def run(self):
        gc = gen_code()
        gc.full_loop = self.full_loop
        gen_code.repeat_asm_block = 1
        if self.bench_name in self.exclude_blk.keys():
            gc.exclude_blk = self.exclude_blk[self.bench_name]
        gc.asm_loop_scale = self.asm_loop_scale
        gc.frame_only = self.frame_only
        gc.use_mt = self.use_mt
        gc.print_flag = self.print_flag
        gc.print_mem_prep = self.print_mem_prep
        gc.bench_name = self.bench_name
        gc.load_asm(self.hotness_path, \
                self.asm_path, self.thread_group[self.bench_name])
        gc.gen_c_file(self.bb_range[0], self.bb_range[1])

def main():
    in_name = sys.argv[1]
    in_frame_only = sys.argv[2]
    in_start_bb = sys.argv[3]
    in_bb_count = sys.argv[4]
    in_full_loop = sys.argv[5]
    in_asm_loop_scale = sys.argv[6]

    pa = parsec_app(in_name)
    pa.full_loop = int(in_full_loop)
    pa.asm_loop_scale = 1/float(in_asm_loop_scale)
    pa.frame_only = bool(int(in_frame_only))
    #pa.bb_range = (int(in_start_bb), int(in_bb_count))
    pa.bb_range = (0, 50000)

    #pa.use_mt = False
    #pa.print_flag = True
    #pa.print_mem_prep = True

    pa.run()

if __name__ == '__main__':
    main()
