use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, rand::Rng, UniformRand};
use core::marker::PhantomData;

/// Input to the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYVRFInput<F> {
    pub x: F,
}

/// Public key for the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYPublicKey<G: AffineRepr> {
    pub pk: G,
}

/// Secret key for the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYSecretKey<F> {
    pub sk: F,
}

/// Output of the Pairing-Free VRF
#[derive(Clone, Debug)]
pub struct PDYVRFOutput<G: AffineRepr> {
    pub y: G,
}

/// Proof for the Pairing-Free VRF using Σ-protocol
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PDYVRFProof<G: AffineRepr> {
    pub t1: G,             // T₁ = g^r
    pub t2: G,             // T₂ = y^r
    pub z: G::ScalarField, // z = r + c(sk + x)
}

/// Public parameters for the Pairing-Free VRF
pub struct PDYVRFPublicParams<G: AffineRepr> {
    pub g: G, // Generator of the prime-order group
}

/// Pairing-Free VRF implementation (P-DY)
pub struct PDYVRF<G: AffineRepr> {
    _phantom: PhantomData<G>,
    pp: PDYVRFPublicParams<G>,
}

impl<G: AffineRepr> PDYVRF<G> {
    /// Initialize a new P-DY VRF with a random generator
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g = G::Group::rand(rng).into_affine();
        PDYVRF {
            _phantom: PhantomData,
            pp: PDYVRFPublicParams { g },
        }
    }

    /// Initialize with a specific generator (useful for testing)
    pub fn new_with_generator(g: G) -> Self {
        PDYVRF {
            _phantom: PhantomData,
            pp: PDYVRFPublicParams { g },
        }
    }

    /// Generate keys: VRF.Gen(1^λ) → (sk, pk)
    /// Sample sk ←$ Z_p*, compute pk = g^sk
    pub fn generate_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> (PDYSecretKey<G::ScalarField>, PDYPublicKey<G>) {
        let sk = G::ScalarField::rand(rng);
        let pk = self.pp.g.mul(sk).into_affine();
        (PDYSecretKey { sk }, PDYPublicKey { pk })
    }

    /// Evaluate: VRF.Eval(sk, x) → y
    /// Compute y = g^(1/(sk+x)) ∈ G
    pub fn evaluate(
        &self,
        input: &PDYVRFInput<G::ScalarField>,
        sk: &PDYSecretKey<G::ScalarField>,
    ) -> Result<PDYVRFOutput<G>, &'static str> {
        // Compute 1/(sk+x)
        let exponent = (sk.sk + input.x).inverse().ok_or("sk + x is zero")?;

        // Compute y = g^(1/(sk+x))
        let y = self.pp.g.mul(exponent).into_affine();

        Ok(PDYVRFOutput { y })
    }

    /// Prove: VRF.Prove(sk, x) → π
    /// Generate proof π using the Σ-protocol
    pub fn prove<R: Rng>(
        &self,
        input: &PDYVRFInput<G::ScalarField>,
        sk: &PDYSecretKey<G::ScalarField>,
        output: &PDYVRFOutput<G>,
        challenge: &G::ScalarField,
        rng: &mut R,
    ) -> Result<PDYVRFProof<G>, &'static str> {
        // 1. Commitment: Sample r ←$ Z_p
        let r = G::ScalarField::rand(rng);

        // Compute T₁ = g^r
        let t1 = self.pp.g.mul(r).into_affine();

        // Compute T₂ = y^r
        let t2 = output.y.mul(r).into_affine();

        // 2. Challenge: In interactive setting, verifier would send c

        // 3. Response: Compute z = r + c(sk + x)
        let z = r + *challenge * (sk.sk + input.x);

        Ok(PDYVRFProof { t1, t2, z })
    }

    /// Verify: VRF.Verify(pk, x, y, π) → {0, 1}
    /// Verify proof using the Σ-protocol verification equations
    pub fn verify(
        &self,
        input: &PDYVRFInput<G::ScalarField>,
        pk: &PDYPublicKey<G>,
        output: &PDYVRFOutput<G>,
        proof: &PDYVRFProof<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        // Compute g^x
        let g_x = self.pp.g.mul(input.x).into_affine();

        // Compute pk·g^x
        let pk_g_x = (pk.pk.into_group() + g_x.into_group()).into_affine();

        // Compute (pk·g^x)^c
        let pk_g_x_c = pk_g_x.mul(*challenge).into_affine();

        // Compute T₁·(pk·g^x)^c
        let rhs1 = (proof.t1.into_group() + pk_g_x_c.into_group()).into_affine();

        // Compute g^z
        let g_z = self.pp.g.mul(proof.z).into_affine();

        // Compute g^c
        let g_c = self.pp.g.mul(*challenge).into_affine();

        // Compute T₂·g^c
        let rhs2 = (proof.t2.into_group() + g_c.into_group()).into_affine();

        // Compute y^z
        let y_z = output.y.mul(proof.z).into_affine();

        // Check: g^z = T₁·(pk·g^x)^c and y^z = T₂·g^c
        g_z == rhs1 && y_z == rhs2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::test_rng;

    #[test]
    fn test_pdyvrf_complete_protocol() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = PDYVRF::<G1Affine>::new(&mut rng);

        // Generate keys
        let (sk, pk) = vrf.generate_keys(&mut rng);

        // Create input
        let input = PDYVRFInput {
            x: Fr::rand(&mut rng),
        };

        // Generate VRF output
        let output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");

        let challenge = Fr::rand(&mut rng);

        // Generate proof
        let proof = vrf
            .prove(&input, &sk, &output, &challenge, &mut rng)
            .expect("Failed to generate proof");

        // Verify
        let is_valid = vrf.verify(&input, &pk, &output, &proof, &challenge);
        assert!(is_valid, "P-DY VRF verification failed");
    }
}
