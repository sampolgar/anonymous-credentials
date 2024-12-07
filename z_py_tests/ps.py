from hashlib import sha256
from py_ecc.fields.field_elements import FQ
from py_ecc.optimized_bls12_381 import G1, G2, G12, FQ, pairing, final_exponentiate, multiply, neg, add, curve_order, is_on_curve
import random


# import galois
# GF = galois.GF(curve_order)


class PublicParameters:
    def __init__(self, n, g1, g2):
        self.n = n
        self.g1 = g1
        self.g2 = g2


class ProofOfKnowledge:
    def __init__(self, pp, cm, blinding_factors):
        self.cm = cm
        self.blinding_factors = blinding_factors
        self.blinding_commitment = None
        self.responses = []

    def blinding_commit(self):
        point = multiply(self.cm.ckg1[0], self.blinding_factors[0])
        for i in range(1, self.pp.n):
            point = add(point, multiply(
                self.cm.ckg1[i], self.blinding_factors[i]))

    def fiat_shamir(self):
        message = str(self.cm.cmg1[0]).encode() + \
            str(self.blinding_commitment[0]).encode()
        return simple_hash_to_field(message)


class Commitment:
    def __init__(self, pp, ck, mi, r):
        self.pp = pp
        self.ckg1 = ck.ckg1
        self.ckg2 = ck.ckg2
        self.mi = mi
        self.r = r
        self.cmg1, self.cmg2 = self.commit()

    def commit(self):

        cmg1 = multiply(self.ckg1[0], self.mi[0])
        cmg2 = multiply(self.ckg2[0], self.mi[0])

        # Add remaining terms
        for i in range(1, self.pp.n):
            cmg1 = add(cmg1, multiply(self.ckg1[i], self.mi[i]))
            cmg2 = add(cmg2, multiply(self.ckg2[i], self.mi[i]))

        # Add randomness term
        cmg1 = add(cmg1, multiply(self.pp.g1, self.r))
        cmg2 = add(cmg2, multiply(self.pp.g2, self.r))

        # test
        if pairing(self.pp.g2, cmg1) == pairing(cmg2, self.pp.g1):
            print("cm_commit pairings are equal!")
        else:
            print("cm_commit pairings aren't equal!")

        return (cmg1, cmg2)

    def cm_rerand(self, r_delta):
        cmg1_r_delta = add(multiply(self.pp.g1, r_delta), self.cmg1)
        cmg2_r_delta = add(multiply(self.pp.g2, r_delta), self.cmg2)

        if pairing(self.pp.g2, cmg1_r_delta) == pairing(cmg2_r_delta, self.pp.g1):
            print("cm_rerand pairing ok")
        else:
            print("cm_rerand pairing not ok")
        self.cmg1 = cmg1_r_delta
        self.cmg2 = cmg2_r_delta
        self.r = self.r + r_delta % curve_order


class CommitmentKey:
    def __init__(self, ckg1, ckg2):
        self.ckg1 = ckg1
        self.ckg2 = ckg2


def genrandom():
    return random.randrange(curve_order-1)
    # return GF(random.randrange(curve_order))


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


def ps_keygen(pp):
    x = genrandom()
    x1 = multiply(pp.g1, x)
    x2 = multiply(pp.g2, x)
    return (x1, x2)


def test_ck(ck, pp):
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


def simple_hash_to_field(message: bytes) -> FQ:
    """
    Simple hash to field - takes bytes, returns an FQ element.
    Good enough for testing/research but not production.
    """
    h = sha256(message).digest()
    # Convert hash to integer and reduce mod field modulus
    return FQ(int.from_bytes(h, 'big') % FQ.field_modulus)

# Test it


def test_hash():
    h1 = simple_hash_to_field(b"test message")
    h2 = simple_hash_to_field(b"test message")
    h3 = simple_hash_to_field(b"different message")

    print(f"Is deterministic: {h1 == h2}")
    print(f"Different inputs give different outputs: {h1 != h3}")
    print(f"Example output: {h1}")


if __name__ == "__main__":
    test_hash()


def main():
    # org key gen
    n = 4
    pp = pp_setup(n)
    ck = cm_setup(pp)
    (sk, vk) = ps_keygen(pp)

    # gen messages in signature as integers
    mi = []
    for i in range(n):
        mi.append(genrandom())

    # gen commitment
    r = genrandom()
    cm = Commitment(pp, ck, mi, r)

    # test rerandomizing it
    r_delta = genrandom()
    cm_rerand = cm.cm_rerand(r_delta)

    # test signing it / obtain & issue
    # 1. prove knowledge of the opening of the commitment

    # 2. request signature over commitment, prove knowledge of the attributes
    # pi = pok_cm_open(cm, blinding_factors)
    # pi = cm: G1, cm':G1, [z_1, z_2,...], e for NIZK
    blinding_factors = []
    for i in range(n):
        blinding_factors.append(genrandom())


main()