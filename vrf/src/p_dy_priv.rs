use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, UniformRand, Zero,
};
use core::marker::PhantomData;

/// Input to the Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivVRFInput<F> {
    pub x: F,   // The input value
    pub r_x: F, // Randomness for input commitment
}

/// Witness for the Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivVRFWitness<F> {
    pub sk: F,   // Secret key
    pub r_sk: F, // Randomness for secret key commitment
    pub x: F,    // Input value
    pub r_x: F,  // Randomness for input commitment
}

/// Public key and commitments for the Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivPublicKey<G: AffineRepr> {
    pub cm_sk: G, // Commitment to secret key: g1^sk * g^r_sk
    pub cm_x: G,  // Commitment to input: g2^x * g^r_x
}

/// Secret key for the Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivSecretKey<F> {
    pub sk: F,   // Secret key
    pub r_sk: F, // Randomness used in commitment
}

/// Output of the Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivVRFOutput<G: AffineRepr> {
    pub y: G, // VRF output y = g^(1/(sk+x))
}

/// Proof for the Private Pairing-Free VRF using Σ-protocol
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PDYPrivVRFProof<G: AffineRepr> {
    pub t1: G,                  // T₁ = g1^a_sk * g^a_r1
    pub t2: G,                  // T₂ = g2^a_x * g^a_r2
    pub ty: G,                  // Tᵧ = y^(a_sk + a_x)
    pub z_sk: G::ScalarField,   // z_sk = a_sk + c*sk
    pub z_x: G::ScalarField,    // z_x = a_x + c*x
    pub z_r_sk: G::ScalarField, // z_r1 = a_r1 + c*r_sk
    pub z_r_x: G::ScalarField,  // z_r2 = a_r2 + c*r_x
    pub z_m: G::ScalarField,    // z_m = (a_sk + a_x) + c*(sk + x)
}

/// Public parameters for the Private Pairing-Free VRF
pub struct PDYPrivVRFPublicParams<G: AffineRepr> {
    pub g: G,  // Generator of the prime-order group
    pub g1: G, // Generator for secret key commitment
    pub g2: G, // Generator for input commitment
}

/// Private Pairing-Free VRF implementation (P-DY-Priv)
pub struct PDYPrivVRF<G: AffineRepr> {
    _phantom: PhantomData<G>,
    pp: PDYPrivVRFPublicParams<G>,
}

impl<G: AffineRepr> PDYPrivVRF<G> {
    /// Initialize a new P-DY-Priv VRF with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = G::Group::rand(rng).into_affine();
        let g1 = G::Group::rand(rng).into_affine();
        let g2 = G::Group::rand(rng).into_affine();

        PDYPrivVRF {
            _phantom: PhantomData,
            pp: PDYPrivVRFPublicParams { g, g1, g2 },
        }
    }

    /// Initialize with specific generators (useful for testing)
    pub fn new_with_generators(g: G, g1: G, g2: G) -> Self {
        PDYPrivVRF {
            _phantom: PhantomData,
            pp: PDYPrivVRFPublicParams { g, g1, g2 },
        }
    }

    /// Generate keys with commitments: VRF.Gen(1^λ) → (sk, pk, cm_sk)
    /// Sample sk ←$ Z_p*, r_sk ←$ Z_p*, compute pk = g^sk, cm_sk = g1^sk * g^r_sk
    pub fn generate_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (PDYPrivSecretKey<G::ScalarField>, PDYPrivPublicKey<G>) {
        let sk = G::ScalarField::rand(rng);
        let r_sk = G::ScalarField::rand(rng);
        // Compute commitment to sk: cm_sk = g1^sk * g^r_sk
        let cm_sk = (self.pp.g1.mul(sk) + self.pp.g.mul(r_sk)).into_affine();

        // Initialize with empty cm_x (will be set when input is provided)
        let cm_x = G::Group::zero().into_affine();

        (
            PDYPrivSecretKey { sk, r_sk },
            PDYPrivPublicKey { cm_sk, cm_x },
        )
    }

    /// Create commitment to input x: cm_x = g2^x * g^r_x
    pub fn commit_to_input(
        &self,
        x: &G::ScalarField,
        rng: &mut impl Rng,
    ) -> (PDYPrivVRFInput<G::ScalarField>, G) {
        let r_x = G::ScalarField::rand(rng);

        // Compute commitment to x: cm_x = g2^x * g^r_x
        let cm_x = (self.pp.g2.mul(*x) + self.pp.g.mul(r_x)).into_affine();

        (PDYPrivVRFInput { x: *x, r_x }, cm_x)
    }

    /// Evaluate: VRF.Eval(sk, x) → y
    /// Compute y = g^(1/(sk+x)) ∈ G
    pub fn evaluate(
        &self,
        witness: &PDYPrivVRFWitness<G::ScalarField>,
    ) -> Result<PDYPrivVRFOutput<G>, &'static str> {
        // Compute 1/(sk+x)
        let exponent = (witness.sk + witness.x).inverse().ok_or("sk + x is zero")?;

        // Compute y = g^(1/(sk+x))
        let y = self.pp.g.mul(exponent).into_affine();

        Ok(PDYPrivVRFOutput { y })
    }

    /// Prove: VRF.Prove(sk, x, r_sk, r_x, y) → π
    /// Generate proof π using the Σ-protocol from Protocol 3
    pub fn prove<R: Rng>(
        &self,
        witness: &PDYPrivVRFWitness<G::ScalarField>,
        output: &PDYPrivVRFOutput<G>,
        rng: &mut R,
    ) -> PDYPrivVRFProof<G> {
        // 1. Commitment phase: Sample random values
        let a_sk = G::ScalarField::rand(rng);
        let a_x = G::ScalarField::rand(rng);
        let a_r_sk = G::ScalarField::rand(rng);
        let a_r_x = G::ScalarField::rand(rng);

        // Compute a_sk + a_x for T_y
        let a_sk_plus_a_x = a_sk + a_x;

        // Compute T₁ = g1^a_sk * g^a_r_sk
        let t1 = (self.pp.g1.mul(a_sk) + self.pp.g.mul(a_r_sk)).into_affine();

        // Compute T₂ = g2^a_x * g^a_r_x
        let t2 = (self.pp.g2.mul(a_x) + self.pp.g.mul(a_r_x)).into_affine();

        // Compute T_y = y^(a_sk + a_x)
        let ty = output.y.mul(a_sk_plus_a_x).into_affine();

        // 2. Challenge: In an interactive setting, this would come from verifier
        // For non-interactive, we'd use Fiat-Shamir with a hash function
        let c = G::ScalarField::rand(rng);

        // 3. Response phase: Compute z values
        let z_sk = a_sk + (c * witness.sk);
        let z_x = a_x + (c * witness.x);
        let z_r_sk = a_r_sk + (c * witness.r_sk);
        let z_r_x = a_r_x + (c * witness.r_x);

        // Compute z_m = (a_sk + a_x) + c * (sk + x)
        let z_m = a_sk_plus_a_x + (c * (witness.sk + witness.x));

        PDYPrivVRFProof {
            t1,
            t2,
            ty,
            z_sk,
            z_x,
            z_r_sk,
            z_r_x,
            z_m,
        }
    }

    /// Generate proof with externally provided challenge
    /// Useful for creating deterministic proofs or when challenge comes from external source
    pub fn prove_with_challenge(
        &self,
        witness: &PDYPrivVRFWitness<G::ScalarField>,
        output: &PDYPrivVRFOutput<G>,
        challenge: &G::ScalarField,
        rng: &mut impl Rng,
    ) -> PDYPrivVRFProof<G> {
        // 1. Commitment phase: Sample random values
        let a_sk = G::ScalarField::rand(rng);
        let a_x = G::ScalarField::rand(rng);
        let a_r_sk = G::ScalarField::rand(rng);
        let a_r_x = G::ScalarField::rand(rng);

        // Compute a_sk + a_x for T_y
        let a_sk_plus_a_x = a_sk + a_x;

        // Compute T₁ = g1^a_sk * g^a_r_sk
        let t1 = (self.pp.g1.mul(a_sk) + self.pp.g.mul(a_r_sk)).into_affine();

        // Compute T₂ = g2^a_x * g^a_r_x
        let t2 = (self.pp.g2.mul(a_x) + self.pp.g.mul(a_r_x)).into_affine();

        // Compute T_y = y^(a_sk + a_x)
        let ty = output.y.mul(a_sk_plus_a_x).into_affine();

        // Use provided challenge
        let c = *challenge;

        // 3. Response phase: Compute z values
        let z_sk = a_sk + (c * witness.sk);
        let z_x = a_x + (c * witness.x);
        let z_r_sk = a_r_sk + (c * witness.r_sk);
        let z_r_x = a_r_x + (c * witness.r_x);

        // Compute z_m = (a_sk + a_x) + c * (sk + x)
        let z_m = a_sk_plus_a_x + (c * (witness.sk + witness.x));

        PDYPrivVRFProof {
            t1,
            t2,
            ty,
            z_sk,
            z_x,
            z_r_sk,
            z_r_x,
            z_m,
        }
    }

    /// Verify: VRF.Verify(cm_sk, cm_x, y, π) → {0, 1}
    /// Verify proof using the Σ-protocol verification equations from Protocol 3
    pub fn verify(
        &self,
        pk_with_commitments: &PDYPrivPublicKey<G>,
        output: &PDYPrivVRFOutput<G>,
        proof: &PDYPrivVRFProof<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        // Check verification equations:

        // 1. T₁ · cm_sk^c ?= g1^z_sk · g^z_r_sk
        let lhs1 =
            (proof.t1.into_group() + pk_with_commitments.cm_sk.mul(*challenge)).into_affine();
        let rhs1 = (self.pp.g1.mul(proof.z_sk) + self.pp.g.mul(proof.z_r_sk)).into_affine();
        let check1 = lhs1 == rhs1;

        // 2. T₂ · cm_x^c ?= g2^z_x · g^z_r_x
        let lhs2 = (proof.t2.into_group() + pk_with_commitments.cm_x.mul(*challenge)).into_affine();
        let rhs2 = (self.pp.g2.mul(proof.z_x) + self.pp.g.mul(proof.z_r_x)).into_affine();
        let check2 = lhs2 == rhs2;

        // 3. T_y · g^c ?= y^z_m
        let lhs3 = (proof.ty.into_group() + self.pp.g.mul(*challenge)).into_affine();
        let rhs3 = output.y.mul(proof.z_m).into_affine();
        let check3 = lhs3 == rhs3;

        // 4. z_m ?= z_sk + z_x
        let check4 = proof.z_m == (proof.z_sk + proof.z_x);

        // All conditions must be satisfied
        check1 && check2 && check3 && check4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::test_rng;

    #[test]
    fn test_pdy_priv_vrf_complete_protocol() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYPrivVRF::<G1Affine>::new(&mut rng);

        // Generate keys with commitment to secret key
        let (sk, mut pk) = vrf.generate_keys(&mut rng);

        // Create input and commitment to input
        let x = Fr::rand(&mut rng);
        let r_x = Fr::rand(&mut rng);

        // Compute commitment to x: cm_x = g2^x * g^r_x
        let cm_x = (vrf.pp.g2.mul(x) + vrf.pp.g.mul(r_x)).into_affine();
        pk.cm_x = cm_x;

        // Create full witness
        let witness = PDYPrivVRFWitness {
            sk: sk.sk,
            r_sk: sk.r_sk,
            x,
            r_x,
        };

        // Generate VRF output
        let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");

        // Generate proof
        let challenge = Fr::rand(&mut rng);
        let proof = vrf.prove_with_challenge(&witness, &output, &challenge, &mut rng);

        // Verify
        let is_valid = vrf.verify(&pk, &output, &proof, &challenge);
        assert!(is_valid, "P-DY-Priv VRF verification failed");
    }
}
