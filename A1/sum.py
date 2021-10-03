#! /usr/bin/python3

add = 0
i=0

while i!=1:

    num = input("Enter Number : ")

    if num.isnumeric() and num != "0":
        add = add + int(num)

    elif num == "0":
        i=1

    else:
        print("Please Enter an Integer or 0 to Exit")

print("Sum = " + str(add))