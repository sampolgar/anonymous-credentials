let pairing_miller_loop = E::multi_miller_loop(&[&a, &c], &[&b, &d]);

&&<E as ark_ec::pairing::Pairing>::G1Prepared: std::convert::Into<<E as ark_ec::pairing::Pairing>::G1Prepared>
The double reference && 

std::convert::Into = convert into is not satisfied
Trying to convert something with double reference.

How to know which to provide?

Function signature shows it wants the actual values:

fn multi_miller_loop<G1, G2>(a: G1, b: G2) -> MillerLoopOutput<E>
where
    G1: Into<E::G1Prepared>,
    G2: Into<E::G2Prepared>,
    E: Pairing,


    where specifies G1,G2 must be the G1Prepared, G2Prepared traits.


Questions
- should I create keys in affine or projective?

## type annotation needed
let (sk: SecretKey<Bls12_381>, pk: PublicKey<Bls12_381>) = keygen(&mut rng, message_count);
struct SecretKey<F: PrimeField, E: Pairing>{}


   let tuples = (0..3)
            .map(|_| gen_pairing_check(&mut rng))
            .collect::<Vec<_>>();
        

collects into a vector