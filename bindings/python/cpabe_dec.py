from __future__ import print_function
import pyopenabe
import time


def cpabe_dec():
    print("Testing Python bindings for PyOpenABE...")

    openabe = pyopenabe.PyOpenABE()

    cpabe = openabe.CreateABEContext("CP-ABE")
    usr_id = "bob"
    mpk = b'0'
    uk = b'0'
    with open("./mpk.txt", "rb") as f:
        mpk = f.read()
        f.close()
    cpabe.importPublicParams(mpk)

    with open("./bob_key.txt", "rb") as f:
        uk = f.read()
        f.close()
    cpabe.importUserKey(usr_id, uk)

    with open("./alice_ct.txt", "rb") as f:
        ct = f.read()
        f.close()



    time_dec = time.time()
    pt2 = cpabe.decrypt(usr_id, ct)
    print("dec_time:", time.time()-time_dec)
    print("bob dec result:", pt2)
    print("CP-ABE dec!")

if __name__ == '__main__':
    cpabe_dec()