import sys


# def replace_special_bytes(str):
#     result = ''
#     for ch in str:


def main(traffic_path):
    HEAD = "[TRAFFIC]"
    ATK = "[attack]:"
    DFC = "[defence]:"
    ATK_LEN = len(ATK)
    DFC_LEN = len(DFC)

    traffic_file = open(traffic_path, "r")
    exp_file = open("exp.py", "wb")

    traffics = traffic_file.read().split(HEAD)

    exp_content = "# -*- coding: utf-8 -*-\nfrom pwn import *\n"

    exp_content += "io = process()\n"
    exp_content += 'io = remote()\n'


    for traffic in traffics:
        if traffic == '':
            continue
        elif traffic.startswith(ATK):
            user_input = traffic[ATK_LEN:]
            exp_content += "io.send(%s)\n"%repr(user_input)
        elif traffic.startswith(DFC):
            # if(len(traffic) <= DFC_LEN+3):
            #     exp_content += "io.recv()\n"
            #     continue
            output = traffic[DFC_LEN:]
            exp_content += "io.recvuntil(%s)\n"%repr(output)
        else:
            print("traffic file error!!")

    print(exp_content)
    exp_file.write(exp_content)
    exp_file.close()







def test():
    main("./18_26_15")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: python traffic2exp.py [traffic_file_path]"
    else:
        traffic_path = sys.argv[1]
    main(traffic_path)

# test()