import sys
from os.path import basename


def gen_mult(output_file, degree_a, degree_b):
    tstates = 0
    size = 0
    degree_a = int(degree_a)
    degree_b = int(degree_b)
    with open(output_file, "w") as output:
        output.write(f"; Generated by {basename(__file__)}\n\n")
        output.write(f"macro {basename(output_file).split('.')[0]}?\n")
        for degree in range(0, degree_a + degree_b - 1):
            is_first = True
            value_in_d = False
            for idxa in range(0, degree_a):
                for idxb in range(0, degree_b):
                    if idxa + idxb == degree:
                        if degree % 2 == 0 and is_first:
                            tstates += 16+16+12
                            size += 3+3+2
                            output.write(f"\tld d, (ix+{idxa})\n")
                            output.write(f"\tld e, (iy+{idxb})\n")
                            output.write("\tmlt de\n")
                        elif value_in_d:
                            tstates += 16+12
                            size += 3+2
                            value_in_d = False
                            register = "bc"
                            output.write(f"\tld c, (iy+{idxb})\n")
                            output.write("\tmlt bc\n")
                        else:
                            tstates += 24+4+16+12
                            size += 3+1+3+2
                            register = "de"
                            value_in_d = True
                            output.write(f"\tld bc, (ix+{idxa})\n")
                            output.write("\tld e, c\n")
                            output.write(f"\tld d, (iy+{idxb})\n")
                            output.write("\tmlt de\n")
                        if degree != 0:
                            tstates += 4
                            size += 1
                            if is_first:
                                output.write("\tex de, hl\n")
                                is_first = False
                            else:
                                output.write(f"\tadd hl, {register}\n")

            tstates += 26+8
            size += 4
            if degree != 0:
                output.write("\tpop de\n")
            else:
                output.write("\tpop hl\n")
            output.write("\tadd hl, de\n")
            output.write(f"\tpush hl\n")
            output.write("\tinc sp\n\n")

        output.write("end macro\n")

    stats = f"; TOTAL CYCLES: {tstates} cycles\n"
    stats += f"; TIME ESTIMATION: {tstates*2800/48000000} seconds\n"
    stats += f"; TOTAL SIZE: {size} bytes\n\n"
    
    with open(output_file, "r+") as output:
        lines = output.readlines()
        lines.insert(0, stats)
        output.seek(0)
        output.writelines(lines)
    print(stats[:-2])

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage:\n\t{basename(__file__)} filename degree_a degree_b")
        exit(-1)

    gen_mult(*sys.argv[1:])
