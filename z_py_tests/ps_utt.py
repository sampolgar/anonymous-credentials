from py_ecc.bls12_381 import G1, add, multiply, neg, curve_order
import random


def generate_proof(g, h, m1, m2, r1, r2, r3, r4, b1, b2, ro1, ro2, ro3, ro4, e):
    # calculate commitments
    C1 = add(multiply(g, m1), multiply(h, r1))
    C2 = add(multiply(g, m2), multiply(h, r2))
    C3 = add(multiply(C1, m2), multiply(h, r3))
    C4 = multiply(h, r4)

    T1 = add(multiply(g, b1), multiply(h, ro1))
    T2 = add(multiply(g, b2), multiply(h, ro2))
    T3 = add(multiply(C1, b2), multiply(h, ro3))
    T4 = multiply(h, ro4)

    zm1 = b1 + e * m1
    zr1 = ro1 + e * r1
    zm2 = b2 + e * m2
    zr2 = ro2 + e * r2
    zr3 = ro3 + e * r3
    zr4 = ro4 + e * r4

    return {
        'C1': C1,
        'C2': C2,
        'C3': C3,
        'C4': C4,
        'T1': T1,
        'T2': T2,
        'T3': T3,
        'T4': T4,
        'zm1': zm1,
        'zr1': zr1,
        'zm2': zm2,
        'zr2': zr2,
        'zr3': zr3,
        'zr4': zr4,
        'e': e,
    }


def verify_proof(g, h, proof):
    lhs1 = add(multiply(proof['C1'], proof['e']), proof['T1'])
    rhs1 = add(multiply(g, proof['zm1']), multiply(h, proof['zr1']))

    # Second equation
    lhs2 = add(multiply(proof['C2'], proof['e']), proof['T2'])
    rhs2 = add(multiply(g, proof['zm2']), multiply(h, proof['zr2']))

    # Third equation
    lhs3 = add(multiply(proof['C3'], proof['e']), proof['T3'])
    rhs3 = add(multiply(proof['C1'], proof['zm2']), multiply(h, proof['zr3']))

    # Fourth equation
    lhs4 = add(multiply(proof['C4'], proof['e']), proof['T4'])
    rhs4 = multiply(h, proof['zr4'])

    if lhs4 == rhs4:
        return True

    # if not all([lhs1 == rhs1, lhs2 == rhs2, lhs3 == rhs3, lhs4 == rhs4]):
    #     print("Verification failed")
    #     return False

    # # Check C3/C4 = g
    # if add(proof['C3'], neg(proof['C4'])) != g:
    #     print("Final equation check failed")
    #     return False


def setup():
    g = G1
    h = multiply(G1, return_randint())
    return g, h


def return_randint():
    return random.randint(1, curve_order - 1)


def main():
    g, h = setup()

    # random values
    m1 = 5
    m2 = pow(m1, -1, curve_order)
    r1 = random.randint(1, curve_order - 1)
    r2 = random.randint(1, curve_order - 1)

    r1, r2, r3, r4, b1, b2, ro1, ro2, ro3, ro4, e = (
        return_randint() for _ in range(11))

    proof = generate_proof(g, h, m1, m2, r1, r2, r3, r4,
                           b1, b2, ro1, ro2, ro3, ro4, e)

    result = verify_proof(g, h, proof)

    print(f"Proof verification result: {result}")


if __name__ == "__main__":
    main()
