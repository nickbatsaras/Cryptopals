#!/usr/bin/python3

PATTERNS = []

with open("08.txt") as FILE:
    for line in FILE:
        line = line.strip()
        for start in range(0, len(line)-16, 16):
            pattern = line[start:start+16]
            if line.count(pattern) > 1 and pattern not in PATTERNS:
                print("AES in ECB detected")
                print("Line: " + line)
                print("Pattern: " + pattern)
                print("Offsets: [%d, %d]\n" % (start, start+16))

                PATTERNS.append(pattern)
