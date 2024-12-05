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

class CommitmentKey:
    def __init__(self, ckg1, ckg2):
        self.ckg1 = ckg1
        self.ckg2 = ckg2

def genrandom():
    return random.randrange(curve_order -1)

def pp_setup(n):
    g1 = multiply(G1, genrandom())
    g2 = multiply(G2, genrandom())
    return PublicParameters(n, g1, g2)

def cm_setup(pp):
    yi = []
    ckg1 = []
    ckg2 = []
    
    for i in range(pp.n):
        yi.append(genrandom())

    for i in range(pp.n):
        ckg1.append(multiply(pp.g1, yi[i]))
        ckg2.append(multiply(pp.g2, yi[i]))

    return CommitmentKey(ckg1, ckg2)

def cm_commit(pp, ck, mi, r):
    ckg1 = ck.ckg1
    ckg2 = ck.ckg2
    cmg1 = G1
    cmg2 = G2
    print("here1")
    test = multiply(ckg1[0], mi[0])
    print("here2")
    for i in range(len(ck.ckg1)):
        cmg1 = add(cmg1, multiply(ckg1[i], mi[i]))
        cmg2 = add(cmg2, multiply(ckg2[i], mi[i]))
    
    cmg1 = add(cmg1, multiply(pp.g1, r))
    cmg2 = add(cmg2, multiply(pp.g2, r))

    # test
    if pairing(pp.g2, cmg1) ==  pairing(cmg2, pp.g1):
        print("pairings are equal!")
    else:
        print("pairings aren't equal!")
    




def ps_keygen(pp):
    x = genrandom()
    x1 = multiply(pp.g1, x)
    x2 = multiply(pp.g2, x)
    return (x1, x2)

def test_ck(ck,pp):
    g1Y = ck[0][0]
    g2Y = ck[1][0]

    for i in range(1, pp.n):
        g1Y = add(g1Y, ck[0][i])
        g2Y = add(g2Y, ck[1][i])
        print(g2Y)

    if pairing(g2Y, pp.g1) == pairing(pp.g2, g1Y):
        print("pairing ok")
    else:
        print("pairing not ok")

def main():
    # org key gen
    n = 4
    pp = pp_setup(n)
    ck = cm_setup(pp)
    (sk, vk) = ps_keygen(pp)

    mi = []  
    for i in range(n):
        mi.append(FQ(genrandom()))

    r = FQ(genrandom())
    cm_commit(pp, ck, mi, r)

    


main()