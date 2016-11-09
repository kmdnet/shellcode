
"""
msf > use payload/windows/exec
msf payload(exec) > set CMD calc
msf payload(exec) > generate -f calc.bin -t raw
"""

import pefile
import sys
import os


def ror32(num,count):
    num1 = (num >> count) & 0xFFFFFFFF
    num2 = (num << (32 - count)) & 0xFFFFFFFF
    return num1 | num2


def char2wchar(string):
    ret = ""
    for ch in string:
      ret+= (ch + '\0')
    return ret


def calc_api_hash(module,api):
    esi = [0] + list(char2wchar(module.upper()+'\0'))
    var_8 = esi[0]
    for x in range(0,len(esi)-1):
        var_8 = ror32(var_8,13)
        var_8 = var_8 + ord(esi[x+1]) & 0xFFFFFFFF
  
    esi = [0] + list(api+"\0")
    edi = esi[0]
    for x in range(0,len(esi)-1):
        edi = ror32(edi,13)
        edi = edi + ord(esi[x+1]) & 0xFFFFFFFF

    return (edi + var_8) & 0xFFFFFFFF


def main():
    argc = len(sys.argv)
    if argc != 2:
        print "python %s <dll_path>" % sys.argv[0]
        sys.exit(1)
    
    hash_list = []
    dll_path = sys.argv[1]
    dll = os.path.basename(dll_path)
    dll_name = os.path.basename(dll_path).split('.')[0]

    pe = pefile.PE(dll_path)
    
    for api in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        api_hash = calc_api_hash(dll,api.name)
        hash_list.append("\thash_%s_%s=0x%08X" % (dll_name,api.name,api_hash))

    print "enum API_HASH{"
    print ",\n".join(hash_list)
    print "};"
    
    
if __name__ == '__main__':
    main()

