from py_ecc.optimized_bls12_381 import G1, G2, G12, FQ, pairing, final_exponentiate, multiply, neg, add, curve_order
import random

# start with datastructures or functions?


# org pp = schemepublicparameters(secparam, n) = (p, secparam, n, g1, g2, e, ..)
# ck = CM.Setup(pp) -> (g1, g1y[i], g2, g2y[i])
# sk, vk = PS.KeyGen(pp, ck). sk = X1, vk = X2
# osk = (g, X), opk = (ck, X2, BG)

class PublicParameters:
    def __init__(self, n, g1, g2):
        self.n = n
        self.g1 = g1
        self.g2 = g2

class Commitment:
    def __init__(self, ck, mi, r):
        self.ck = ck
        self.mi = mi
        self.r = r

def genrandom():
    return random.randrange(curve_order -1)

def pp_setup(n):
    g1 = multiply(G1, genrandom())
    g2 = multiply(G2, genrandom())
    print(g1, g2)
    return PublicParameters(n, g1, g2)

def cm_setup(pp):
    yi = []
    g1yi = []
    g2yi = []
    
    for i in range(pp.n):
        yi.append(genrandom())

    for i in range(pp.n):
        g1yi.append(multiply(pp.g1, yi[i]))
        g2yi.append(multiply(pp.g2, yi[i]))

    return (g1yi, g2yi)

# def cm_com(ck, mi, r):



def ps_keygen(pp):
    x = genrandom()
    x1 = multiply(pp.g1, x)
    x2 = multiply(pp.g2, x)
    return (x1, x2)


# def org_keygen(n):


def test_ck(ck,pp):
    g1Y = ck[0][0]
    g2Y = ck[1][0]
    for i in range(1, pp.n):
        g1Y = add(g1Y, ck[0][i])
        g2Y = add(g2Y, ck[1][i])

    if pairing(pp.g1, g2Y) == pairing(g1Y, pp.g2):
        print("pairing ok")
    else:
        print("pairing not ok")



def main():
    # org key gen
    n = 4
    pp = pp_setup(n)
    ck = cm_setup(pp)
    (sk, vk) = ps_keygen(pp)

    # obtain
    m = []
    for i in range(n):
        m.append(FQ(genrandom()))
    
    test_ck(ck, pp)
    



    


    # parse opk = ck, pp, vk
    # Compute (cm1, cm2) = CM.Com(ck, mi, r)




    # Run picm = zkp.comopen()

    


main()