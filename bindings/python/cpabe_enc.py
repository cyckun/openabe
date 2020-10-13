from __future__ import print_function
import pyopenabe
import time
import rsa


def cpabe_enc():
    print("Testing Python bindings for PyOpenABE...")

    openabe = pyopenabe.PyOpenABE()

    cpabe = openabe.CreateABEContext("CP-ABE")

    with open("./mpk.txt", "rb") as f:
        mpk = f.read()
        f.close()

    cpabe.importPublicParams(mpk)
    pt1 = b"hello world!"
    # ct = cpabe.encrypt("((one or two) and three)", pt1)
    time_enc = time.time()
    file_policy = "(((Dept:SecurityResearch) or (level >= 4 )) and (Company:ByteDance)) and date < April 18, 2021"
    ct = cpabe.encrypt(file_policy, pt1)
    print("enc time:", time.time()-time_enc)

    with open("./alice_ct.txt", "wb") as f:
        f.write(ct)
        f.close()
    print("CP-ABE enc end.")

if __name__ == '__main__':
   # rsa_test()
    cpabe_enc()