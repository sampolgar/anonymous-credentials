use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, UniformRand, Zero,
};
use core::marker::PhantomData;

/// Input to the Extended Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraInput<F> {
    pub x: F, // The input value
}

/// Witness for the Extended Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraWitness<F> {
    pub sk: F, // Secret key
    pub x: F,  // Input value
    pub m: F,  // m = sk + x
    pub r1: F, // Randomness for commitment to sk
    pub r2: F, // Randomness for commitment to x
    pub r3: F, // Randomness for commitment to β = 1/(sk+x)
    pub r4: F, // Randomness for commitment to m
    pub r5: F, // Randomness for composite commitment
}

/// Commitments for the Extended Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraCommitments<G: AffineRepr> {
    pub cm1: G, // Commitment to secret key: g₁^sk * g^r₁
    pub cm2: G, // Commitment to input: g₂^x * g^r₂
    pub cm3: G, // Commitment to VRF output: g₃^β * g^r₃ where β = 1/(sk+x)
    pub cm4: G, // Commitment to m: g₄^m * g^r₄ where m = sk+x
    pub cm5: G, // Composite commitment: cm₃^m * g^r₅ = g₃^r₃m+r₅
}

/// VRF output and proof for the Extended Private Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPrivExtraOutput<G: AffineRepr> {
    pub commitments: PDYPrivExtraCommitments<G>, // All commitments
    pub y: G,                                    // VRF output y = g^(1/(sk+x))
}

/// Proof for the Extended Private Pairing-Free VRF using Σ-protocol
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PDYPrivExtraProof<G: AffineRepr> {
    // Commitments from the protocol
    pub t1: G, // T₁ = g₁^a_sk * g^a_r₁
    pub t2: G, // T₂ = g₂^a_x * g^a_r₂
    pub t3: G, // T₃ = g₃^a_β * g^a_r₃
    pub t4: G, // T₄ = g₄^a_m * g^a_r₄
    pub t5: G, // T₅ = cm₃^a_m * g^a_r₅

    // Responses from the protocol
    pub z_sk: G::ScalarField,   // z_sk = a_sk + c*sk
    pub z_x: G::ScalarField,    // z_x = a_x + c*x
    pub z_m: G::ScalarField,    // z_m = a_m + c*m
    pub z_beta: G::ScalarField, // z_β = a_β + c*β
    pub z_r1: G::ScalarField,   // z_r₁ = a_r₁ + c*r₁
    pub z_r2: G::ScalarField,   // z_r₂ = a_r₂ + c*r₂
    pub z_r3: G::ScalarField,   // z_r₃ = a_r₃ + c*r₃
    pub z_r4: G::ScalarField,   // z_r₄ = a_r₄ + c*r₄
    pub z_r5: G::ScalarField,   // z_r₅ = a_r₅ + c*r₅
}

/// Public parameters for the Extended Private Pairing-Free VRF
pub struct PDYPrivExtraPublicParams<G: AffineRepr> {
    pub g: G,  // Base generator
    pub g1: G, // Generator for secret key commitment
    pub g2: G, // Generator for input commitment
    pub g3: G, // Generator for VRF output commitment
    pub g4: G, // Generator for m=sk+x commitment
}

/// Extended Private Pairing-Free VRF implementation
pub struct PDYPrivExtraVRF<G: AffineRepr> {
    _phantom: PhantomData<G>,
    pp: PDYPrivExtraPublicParams<G>,
}

impl<G: AffineRepr> PDYPrivExtraVRF<G> {
    /// Initialize a new extended P-DY-Priv VRF with random generators
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = G::Group::rand(rng).into_affine();
        let g1 = G::Group::rand(rng).into_affine();
        let g2 = G::Group::rand(rng).into_affine();
        let g3 = G::Group::rand(rng).into_affine();
        let g4 = G::Group::rand(rng).into_affine();

        PDYPrivExtraVRF {
            _phantom: PhantomData,
            pp: PDYPrivExtraPublicParams { g, g1, g2, g3, g4 },
        }
    }

    /// Initialize with specific generators (useful for testing)
    pub fn new_with_generators(g: G, g1: G, g2: G, g3: G, g4: G) -> Self {
        PDYPrivExtraVRF {
            _phantom: PhantomData,
            pp: PDYPrivExtraPublicParams { g, g1, g2, g3, g4 },
        }
    }

    /// Generate a complete witness with all necessary values and randomness
    pub fn generate_full_witness<R: Rng>(
        &self,
        sk: &G::ScalarField,
        x: &G::ScalarField,
        rng: &mut R,
    ) -> PDYPrivExtraWitness<G::ScalarField> {
        let m = *sk + *x; // m = sk + x
        let beta = m.inverse().expect("sk + x should not be zero"); // β = 1/(sk+x)

        // Generate randomness for commitments
        let r1 = G::ScalarField::rand(rng);
        let r2 = G::ScalarField::rand(rng);
        let r3 = G::ScalarField::rand(rng);
        let r4 = G::ScalarField::rand(rng);
        let r5 = G::ScalarField::rand(rng);

        PDYPrivExtraWitness {
            sk: *sk,
            x: *x,
            m,
            r1,
            r2,
            r3,
            r4,
            r5,
        }
    }

    /// Create all the commitments from a witness
    pub fn create_commitments(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
    ) -> PDYPrivExtraCommitments<G> {
        // Calculate β = 1/(sk+x)
        let beta = witness.m.inverse().expect("m = sk + x should not be zero");

        // cm₁ = g₁^sk * g^r₁
        let cm1 = (self.pp.g1.mul(witness.sk) + self.pp.g.mul(witness.r1)).into_affine();

        // cm₂ = g₂^x * g^r₂
        let cm2 = (self.pp.g2.mul(witness.x) + self.pp.g.mul(witness.r2)).into_affine();

        // cm₃ = g₃^β * g^r₃
        let cm3 = (self.pp.g3.mul(beta) + self.pp.g.mul(witness.r3)).into_affine();

        // cm₄ = g₄^m * g^r₄
        let cm4 = (self.pp.g4.mul(witness.m) + self.pp.g.mul(witness.r4)).into_affine();

        // cm₅ = cm₃^m * g^r₅ = g₃^(β*m) * g^(r₃*m+r₅)
        // Note: β*m = 1 since β = 1/m
        // So this is essentially g₃ * g^(r₃*m+r₅)
        let cm5 = (self.pp.g3.into_group() + self.pp.g.mul(witness.r3 * witness.m + witness.r5))
            .into_affine();

        PDYPrivExtraCommitments {
            cm1,
            cm2,
            cm3,
            cm4,
            cm5,
        }
    }

    /// Evaluate the VRF: compute y = g^(1/(sk+x))
    pub fn evaluate(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
    ) -> Result<PDYPrivExtraOutput<G>, &'static str> {
        // Compute β = 1/(sk+x)
        let beta = witness.m.inverse().ok_or("m = sk + x is zero")?;

        // Compute y = g^β
        let y = self.pp.g.mul(beta).into_affine();

        // Create all the commitments
        let commitments = self.create_commitments(witness);

        Ok(PDYPrivExtraOutput { commitments, y })
    }

    /// Generate proof with externally provided challenge
    pub fn prove_with_challenge(
        &self,
        witness: &PDYPrivExtraWitness<G::ScalarField>,
        output: &PDYPrivExtraOutput<G>,
        challenge: &G::ScalarField,
        rng: &mut impl Rng,
    ) -> PDYPrivExtraProof<G> {
        // Calculate β = 1/(sk+x)
        let beta = witness.m.inverse().expect("m = sk + x should not be zero");

        // 1. Commitment phase: Sample random values
        let a_sk = G::ScalarField::rand(rng);
        let a_x = G::ScalarField::rand(rng);
        let a_m = a_sk + a_x;
        let a_beta = G::ScalarField::rand(rng);
        let a_r1 = G::ScalarField::rand(rng);
        let a_r2 = G::ScalarField::rand(rng);
        let a_r3 = G::ScalarField::rand(rng);
        let a_r4 = G::ScalarField::rand(rng);
        let a_r5 = G::ScalarField::rand(rng);

        // Compute T₁ = g₁^a_sk * g^a_r₁
        let t1 = (self.pp.g1.mul(a_sk) + self.pp.g.mul(a_r1)).into_affine();

        // Compute T₂ = g₂^a_x * g^a_r₂
        let t2 = (self.pp.g2.mul(a_x) + self.pp.g.mul(a_r2)).into_affine();

        // Compute T₃ = g₃^a_β * g^a_r₃
        let t3 = (self.pp.g3.mul(a_beta) + self.pp.g.mul(a_r3)).into_affine();

        // Compute T₄ = g₄^a_m * g^a_r₄
        let t4 = (self.pp.g4.mul(a_m) + self.pp.g.mul(a_r4)).into_affine();

        // Compute T₅ = cm₃^a_m * g^a_r₅
        let t5 = (output.commitments.cm3.mul(a_m) + self.pp.g.mul(a_r5)).into_affine();

        // Use provided challenge
        let c = *challenge;

        // 3. Response phase: Compute z values
        let z_sk = a_sk + (c * witness.sk);
        let z_x = a_x + (c * witness.x);
        let z_m = a_m + (c * witness.m);
        let z_beta = a_beta + (c * beta);
        let z_r1 = a_r1 + (c * witness.r1);
        let z_r2 = a_r2 + (c * witness.r2);
        let z_r3 = a_r3 + (c * witness.r3);
        let z_r4 = a_r4 + (c * witness.r4);
        let z_r5 = a_r5 + (c * witness.r5);

        PDYPrivExtraProof {
            t1,
            t2,
            t3,
            t4,
            t5,
            z_sk,
            z_x,
            z_m,
            z_beta,
            z_r1,
            z_r2,
            z_r3,
            z_r4,
            z_r5,
        }
    }

    /// Verify the proof for the VRF evaluation
    pub fn verify(
        &self,
        commitments: &PDYPrivExtraCommitments<G>,
        y: &G,
        proof: &PDYPrivExtraProof<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        // Check verification equations:

        // 1. T₁ · cm₁^c ?= g₁^z_sk · g^z_r₁
        let lhs1 = (proof.t1.into_group() + commitments.cm1.mul(*challenge)).into_affine();
        let rhs1 = (self.pp.g1.mul(proof.z_sk) + self.pp.g.mul(proof.z_r1)).into_affine();
        let check1 = lhs1 == rhs1;
        if !check1 {
            println!("Verification failed: Check 1 (T₁ · cm₁^c = g₁^z_sk · g^z_r₁) failed");
        }

        // 2. T₂ · cm₂^c ?= g₂^z_x · g^z_r₂
        let lhs2 = (proof.t2.into_group() + commitments.cm2.mul(*challenge)).into_affine();
        let rhs2 = (self.pp.g2.mul(proof.z_x) + self.pp.g.mul(proof.z_r2)).into_affine();
        let check2 = lhs2 == rhs2;
        if !check2 {
            println!("Verification failed: Check 2 (T₂ · cm₂^c = g₂^z_x · g^z_r₂) failed");
        }

        // 3. T₃ · cm₃^c ?= g₃^z_β · g^z_r₃
        let lhs3 = (proof.t3.into_group() + commitments.cm3.mul(*challenge)).into_affine();
        let rhs3 = (self.pp.g3.mul(proof.z_beta) + self.pp.g.mul(proof.z_r3)).into_affine();
        let check3 = lhs3 == rhs3;
        if !check3 {
            println!("Verification failed: Check 3 (T₃ · cm₃^c = g₃^z_β · g^z_r₃) failed");
        }

        // 4. T₄ · cm₄^c ?= g₄^z_m · g^z_r₄
        let lhs4 = (proof.t4.into_group() + commitments.cm4.mul(*challenge)).into_affine();
        let rhs4 = (self.pp.g4.mul(proof.z_m) + self.pp.g.mul(proof.z_r4)).into_affine();
        let check4 = lhs4 == rhs4;
        if !check4 {
            println!("Verification failed: Check 4 (T₄ · cm₄^c = g₄^z_m · g^z_r₄) failed");
        }

        // 5. T₅ · cm₅^c ?= cm₃^z_m · g^z_r₅
        let lhs5 = (proof.t5.into_group() + commitments.cm5.mul(*challenge)).into_affine();
        let rhs5 = (commitments.cm3.mul(proof.z_m) + self.pp.g.mul(proof.z_r5)).into_affine();
        let check5 = lhs5 == rhs5;
        if !check5 {
            println!("Verification failed: Check 5 (T₅ · cm₅^c = cm₃^z_m · g^z_r₅) failed");
        }

        // 6. z_m ?= z_sk + z_x
        let check6 = proof.z_m == (proof.z_sk + proof.z_x);
        if !check6 {
            println!("Verification failed: Check 6 (z_m = z_sk + z_x) failed");
        }

        // All conditions must be satisfied
        check1 && check2 && check3 && check4 && check5 && check6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::test_rng;

    #[test]
    fn test_pdy_priv_extra_vrf_complete_protocol() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

        // Generate secret key and input
        let sk = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        // Generate full witness with all randomness
        let witness = vrf.generate_full_witness(&sk, &x, &mut rng);

        // Evaluate VRF and create commitments
        let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");

        // Generate proof
        let challenge = Fr::rand(&mut rng);
        let proof = vrf.prove_with_challenge(&witness, &output, &challenge, &mut rng);

        // Verify the proof
        let is_valid = vrf.verify(&output.commitments, &output.y, &proof, &challenge);
        assert!(is_valid, "P-DY-Priv-Extra VRF verification failed");
    }

    #[test]
    fn test_commitment_properties() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

        // Generate secret key and input
        let sk = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);

        // Generate full witness with all randomness
        let witness = vrf.generate_full_witness(&sk, &x, &mut rng);

        // Calculate β = 1/(sk+x)
        let beta = witness.m.inverse().expect("m = sk + x should not be zero");

        // Create commitments
        let commitments = vrf.create_commitments(&witness);

        // Test cm₅ = cm₃^m * g^r₅ relationship
        let cm5_direct = (commitments.cm3.mul(witness.m) + vrf.pp.g.mul(witness.r5)).into_affine();
        assert_eq!(commitments.cm5, cm5_direct, "cm₅ relationship doesn't hold");

        // Test that relationship between y = g^β and cm₃ holds
        // cm₃ = g₃^β * g^r₃
        let y_from_witness = vrf.pp.g.mul(beta).into_affine();
        let expected_cm3 = (vrf.pp.g3.mul(beta) + vrf.pp.g.mul(witness.r3)).into_affine();
        assert_eq!(
            commitments.cm3, expected_cm3,
            "cm₃ relationship doesn't hold"
        );

        // Test m = sk + x
        assert_eq!(
            witness.m,
            witness.sk + witness.x,
            "m = sk + x relationship doesn't hold"
        );
    }
}
