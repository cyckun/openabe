from __future__ import print_function
import pyopenabe
import time
import rsa


def cpabe_usrkey():   # TA operate; not import msk; flag to check whether msk has existed.
    print("Testing Python bindings for PyOpenABE...")

    openabe = pyopenabe.PyOpenABE()

    cpabe = openabe.CreateABEContext("CP-ABE")

    with open("./mpk.txt", 'rb') as f:
        mpk_load = f.read()
        f.close()
    with open("./msk.txt", 'rb') as f:
        msk_load = f.read()
        f.close()

    cpabe.importSecretParams(msk_load)
    cpabe.importPublicParams(mpk_load)

    #cpabe.keygen("|two|three|", "alice")
    usr_id = "bob"
    usr_attri = "Dept:SecurityResearch|level = 2| Company:ByteDance|Sex:female"
    cpabe.keygen(usr_attri, usr_id)

    uk = cpabe.exportUserKey(usr_id)
    with open("./bob_key.txt", 'wb') as f:
        f.write(uk)
        f.close()


    print("CP-ABE userkey gen end!")

if __name__ == '__main__':
   # rsa_test()
    cpabe_usrkey()