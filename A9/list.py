#! /usr/bin/python3

import itertools

ipsrc, ipdst, ipprt, srcp, dstp = "0", "0", "0", "0", "0"
# ipsrc, ipdst, ipprt, srcp, dstp = 0, 0, 0, 0, 0
# ipsrc, ipdst, ipprt, srcp, dstp = str(ipsrc), str(ipdst), str(ipprt), str(srcp), str(dstp)

packet = [ipsrc, ipdst, ipprt, srcp, dstp]
check = []

i, n, k = 0, 2, 5

permutations_with_replacement = itertools.product(range(n), repeat=k)
for permutation in permutations_with_replacement:
    
    # print(permutation)

    for value in packet:
        
        replacement = permutation[i]
        if  replacement == 1:
            value = "n"

        check.append(value)
        i = i + 1

    check_tup = tuple(check)

    # print(type(check_tup[0]))

    print(str(check_tup[0]) + " " + str(check_tup[1]) + " " + str(check_tup[2]) + " " + str(check_tup[3]) + " " + str(check_tup[4]))

    check = []
    i=0
