import pefile
import sys
import os


def ror32(num,count):
    num1 = (num >> count) & 0xFFFFFFFF
    num2 = (num << (32 - count)) & 0xFFFFFFFF
    return num1 | num2


def calc_api_hash(string):
    esi = [0] + list(string)
    edi = esi[0]
    for x in range(0,len(esi)-1):
        edi = ror32(edi,13)
        edi = edi + ord(esi[x+1]) & 0xFFFFFFFF
    return edi


def main():
    argc = len(sys.argv)
    if argc != 2:
        print "python %s <dll_path>" % sys.argv[0]
        sys.exit(1)

    hash_list = []
    dll_path = sys.argv[1]
    dll_name = os.path.basename(dll_path).split('.')[0]

    pe = pefile.PE(dll_path)
    
    for api in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        api_hash = calc_api_hash(api.name)
        hash_list.append("\thash_%s_%s=0x%08X" % (dll_name,api.name,api_hash))

    print "enum API_HASH{"
    print ",\n".join(hash_list)
    print "};"
    

if __name__ == '__main__':
    main()





