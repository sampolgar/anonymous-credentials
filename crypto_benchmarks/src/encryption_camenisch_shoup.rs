use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{Rng, RngCore};
use ark_std::test_rng;
use sha2::{Digest, Sha256};
use std::ops::Mul;

// Public parameters: generators G, H, K in G1
pub struct PublicParams {
    pub g: G1Affine,
    pub h: G1Affine,
    pub k: G1Affine,
}

// Secret key: scalars x, y such that H = x * G, K = y * G
pub struct SecretKey {
    pub x: Fr,
    pub y: Fr,
}

// Ciphertext: (U, E, V, t)
pub struct Ciphertext {
    pub u: G1Affine,
    pub e: G1Affine,
    pub v: G1Affine,
    pub t: Fr, // Hash(U, E, L)
}

// Zero-knowledge proof for well-formed ciphertext
pub struct WellFormedProof {
    pub a1: G1Affine,
    pub a2: G1Affine,
    pub a3: G1Affine,
    pub z_r: Fr,
    pub z_m: Fr,
    pub c: Fr,
}

impl PublicParams {
    pub fn new<R: RngCore>(rng: &mut R) -> (Self, SecretKey) {
        let g = G1Affine::rand(rng);
        let x = Fr::rand(rng);
        let y = Fr::rand(rng);
        let h = g.mul(x).into_affine();
        let k = g.mul(y).into_affine();
        (PublicParams { g, h, k }, SecretKey { x, y })
    }
}

impl SecretKey {
    /// Encrypt a message M (point on G1) with label L
    pub fn encrypt<R: RngCore>(
        &self,
        pp: &PublicParams,
        m: G1Affine,
        label: &[u8],
        rng: &mut R,
    ) -> Ciphertext {
        let r = Fr::rand(rng);
        let u = pp.g.mul(r).into_affine();
        let e = (pp.h.mul(r) + m).into_affine();
        let mut hasher = Sha256::new();

        let mut u_bytes = Vec::new();
        u.serialize_compressed(&mut u_bytes).unwrap();
        hasher.update(&u_bytes);

        // Serialize e to compressed bytes
        let mut e_bytes = Vec::new();
        e.serialize_compressed(&mut e_bytes).unwrap();
        hasher.update(&e_bytes);

        // hasher.update(u.to_compressed());
        // hasher.update(e.to_compressed());
        // hasher.update(label);
        let hash_bytes = hasher.finalize();
        let t = Fr::from_le_bytes_mod_order(&hash_bytes);
        let v = (pp.k.mul(r) + pp.g.mul(t)).into_affine();
        Ciphertext { u, e, v, t }
    }

    /// Decrypt a ciphertext with label L
    pub fn decrypt(&self, pp: &PublicParams, ct: &Ciphertext, label: &[u8]) -> Option<G1Affine> {
        let u_y = ct.u.mul(self.y).into_affine();
        let v_check = (u_y + pp.g.mul(ct.t)).into_affine();
        if ct.v != v_check {
            return None; // Tag verification failed
        }
        let m = (ct.e.into_group() - ct.u.mul(self.x)).into_affine();
        Some(m)
    }
}

/// Prove that the ciphertext is well-formed
pub fn prove_well_formed<R: RngCore>(
    pp: &PublicParams,
    ct: &Ciphertext,
    m: G1Affine,
    m_scalar: Fr, // Assuming m = m_scalar * G
    r: Fr,
    rng: &mut R,
) -> WellFormedProof {
    let s_r = Fr::rand(rng);
    let s_m = Fr::rand(rng);
    let a1 = pp.g.mul(s_r).into_affine(); // s_r * G
    let a2 = (pp.h.mul(s_r) + pp.g.mul(s_m)).into_affine(); // s_r * H + s_m * G
    let a3 = pp.k.mul(s_r).into_affine(); // s_r * K
    let c = Fr::rand(rng); // In practice, hash(a1, a2, a3)
    let z_r = s_r + c * r;
    let z_m = s_m + c * m_scalar;
    WellFormedProof {
        a1,
        a2,
        a3,
        z_r,
        z_m,
        c,
    }
}

/// Verify the proof of well-formedness
pub fn verify_well_formed(pp: &PublicParams, ct: &Ciphertext, proof: &WellFormedProof) -> bool {
    let lhs1 = (proof.a1 + ct.u.mul(proof.c)).into_affine();
    let rhs1 = pp.g.mul(proof.z_r).into_affine();
    if lhs1 != rhs1 {
        return false;
    }
    let lhs2 = (proof.a2 + ct.e.mul(proof.c)).into_affine();
    let rhs2 = (pp.h.mul(proof.z_r) + pp.g.mul(proof.z_m)).into_affine();
    if lhs2 != rhs2 {
        return false;
    }
    let v_minus_tg = (ct.v.into_group() - pp.g.mul(ct.t)).into_affine();
    let lhs3 = (proof.a3 + v_minus_tg.mul(proof.c)).into_affine();
    let rhs3 = pp.k.mul(proof.z_r).into_affine();
    if lhs3 != rhs3 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    #[test]
    fn test_elliptic_camenisch_shoup() {
        let mut rng = test_rng();
        let (pp, sk) = PublicParams::new(&mut rng);
        let m_scalar = Fr::rand(&mut rng);
        let m = pp.g.mul(m_scalar).into_affine();
        let label = b"test_label";
        let r = Fr::rand(&mut rng);
        let ct = sk.encrypt(&pp, m, label, &mut rng);
        let decrypted = sk.decrypt(&pp, &ct, label).expect("Decryption failed");
        assert_eq!(decrypted, m, "Decrypted message does not match original");
        let proof = prove_well_formed(&pp, &ct, m, m_scalar, r, &mut rng);
        assert!(
            verify_well_formed(&pp, &ct, &proof),
            "Proof verification failed"
        );
    }
}
