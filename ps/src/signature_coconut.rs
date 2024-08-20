use crate::keygen_coconut::{AggregatePublicKey, PartialSecretKey, ThresholdKeys};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, Zero,
};

#[derive(Clone, Debug)]
pub struct CoconutSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> CoconutSignature<E>
where
    E::ScalarField: PrimeField,
    E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
{
    pub fn partial_sign(
        partial_sk: &PartialSecretKey<E::ScalarField>,
        h: &E::G1Affine,
        messages: &[E::ScalarField],
    ) -> Self {
        assert_eq!(
            messages.len(),
            partial_sk.y_i.len(),
            "Number of messages must match number of attributes"
        );

        let sigma1 = *h;
        let mut exponent = partial_sk.x_i;
        for (&m, &y) in messages.iter().zip(partial_sk.y_i.iter()) {
            exponent += m * y;
        }
        let sigma2 = h.mul(exponent).into_affine();

        println!("Partial Signature:");
        println!("  sigma1: {:?}", sigma1);
        println!("  sigma2: {:?}", sigma2);

        Self { sigma1, sigma2 }
    }

    pub fn aggregate_signatures(partial_signatures: &[Self], threshold: usize) -> Self {
        assert!(
            partial_signatures.len() >= threshold,
            "Not enough partial signatures"
        );

        let sigma1 = partial_signatures[0].sigma1; // All sigma1 are the same
        let mut sigma2 = E::G1::zero();

        for (i, partial_sig) in partial_signatures.iter().take(threshold).enumerate() {
            let mut lambda_i = E::ScalarField::one();
            for (j, _) in partial_signatures.iter().take(threshold).enumerate() {
                if i != j {
                    let i_plus_1 = E::ScalarField::from((i + 1) as u64);
                    let j_plus_1 = E::ScalarField::from((j + 1) as u64);
                    lambda_i *= j_plus_1 * (j_plus_1 - i_plus_1).inverse().unwrap();
                }
            }
            sigma2 += partial_sig.sigma2.mul(lambda_i);
        }

        let result = Self {
            sigma1,
            sigma2: sigma2.into_affine(),
        };

        println!("Aggregated Signature:");
        println!("  sigma1: {:?}", result.sigma1);
        println!("  sigma2: {:?}", result.sigma2);

        result
    }

    pub fn verify(
        &self,
        messages: &[E::ScalarField],
        aggregate_pk: &AggregatePublicKey<E>,
    ) -> bool {
        assert_eq!(
            messages.len(),
            aggregate_pk.g2_y.len(),
            "Number of messages must match number of attributes in public key"
        );

        let mut lhs = E::pairing(self.sigma1, aggregate_pk.g2_x);
        for (m, g2_y) in messages.iter().zip(aggregate_pk.g2_y.iter()) {
            lhs += E::pairing(self.sigma1.mul(*m), g2_y);
        }

        let rhs = E::pairing(self.sigma2, aggregate_pk.g2);

        println!("Verification:");
        println!("  LHS: {:?}", lhs);
        println!("  RHS: {:?}", rhs);
        println!("  Messages: {:?}", messages);

        lhs == rhs
    }

    pub fn randomize(&self, r: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: self.sigma2.mul(r).into_affine(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen_coconut::distributed_keygen;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ff::Field;
    use ark_std::test_rng;

    #[test]
    fn test_coconut_signature_multi_attribute() {
        let mut rng = test_rng();
        let n = 5;
        let t = 3;
        let attribute_count = 3;

        println!("1. Generating keys");
        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, attribute_count);
        println!("Aggregate public key: {:?}", aggregate_pk);

        let messages: Vec<Fr> = (0..attribute_count).map(|_| Fr::rand(&mut rng)).collect();
        let h = G1Affine::rand(&mut rng);

        println!("2. Messages and h:");
        println!("Messages: {:?}", messages);
        println!("h: {:?}", h);

        println!("3. Generating partial signatures");
        let partial_signatures: Vec<_> = threshold_keys
            .iter()
            .map(|tk| {
                let sig = CoconutSignature::partial_sign(&tk.partial_secret_key, &h, &messages);
                println!("Partial signature: {:?}", sig);
                sig
            })
            .collect();

        // println!("4. Checking partial signature validity");
        // for (i, sig) in partial_signatures.iter().enumerate() {
        //     let pk = &threshold_keys[i].partial_public_key;
        //     let mut lhs = Bls12_381::pairing(sig.sigma2, aggregate_pk.g2);
        //     let mut rhs = Bls12_381::pairing(sig.sigma1, pk.g2_x_i);
        //     for (&m, &g2_y_i) in messages.iter().zip(pk.g2_y_i.iter()) {
        //         rhs += Bls12_381::pairing(sig.sigma1.mul(m), g2_y_i);
        //     }
        //     println!("Partial signature {} validity: {}", i, lhs == rhs);
        //     assert!(lhs == rhs, "Partial signature {} is invalid", i);
        // }

        println!("5. Aggregating signatures");
        let signature = CoconutSignature::aggregate_signatures(&partial_signatures, t);

        println!("6. Verifying aggregated signature");
        let is_valid = signature.verify(&messages, &aggregate_pk);
        println!("Aggregated signature validity: {}", is_valid);
        assert!(is_valid, "Aggregated signature verification failed");

        println!("7. Testing randomization");
        let r = Fr::rand(&mut rng);
        println!("Randomization factor r: {:?}", r);
        let randomized_signature = signature.randomize(&r);
    }
}
