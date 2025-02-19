use crate::commitment::Commitment;
use crate::keygen::{KeyPair, KeyPairImproved};
use crate::publicparams::PublicParams;
use crate::signature::{PSSignature, PSUTTSignatureImproved};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul};
use ark_std::rand::Rng;

pub fn g1_commit<E: Pairing>(
    pp: &PublicParams<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G1Affine {
    assert!(messages.len() <= pp.ckg1.len(), "m.len should be < ck!");
    let ck = &pp.ckg1[..messages.len()];

    let temp = E::G1::msm_unchecked(ck, messages);
    let g1_r = pp.g1.mul(r);
    temp.add(g1_r).into_affine()
}

pub fn g1_commit_schnorr<E: Pairing>(
    pp: &PublicParams<E>,
    exponents: &[E::ScalarField],
) -> E::G1Affine {
    assert!(exponents.len() <= pp.ckg1.len(), "m.len should be < ck!");
    let bases = pp.get_g1_bases();
    let com = E::G1::msm_unchecked(&bases, exponents).into_affine();
    com
}

pub fn g2_commit<E: Pairing>(
    pp: &PublicParams<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G2Affine {
    assert!(messages.len() <= pp.ckg2.len(), "message.len > ckg2.len");
    // cut ckg2 to the size of m
    let ck = &pp.ckg2[..messages.len()];
    let temp = E::G2::msm_unchecked(ck, messages);
    let g2_r = pp.g2.mul(r);
    temp.add(g2_r).into_affine()
}

pub fn g2_commit_schnorr<E: Pairing>(
    pp: &PublicParams<E>,
    exponents: &[E::ScalarField],
) -> E::G2Affine {
    assert!(exponents.len() <= pp.ckg2.len(), "m.len should be < ck!");
    let bases = pp.get_g2_bases();
    let com = E::G2::msm_unchecked(&bases, exponents).into_affine();
    com
}

// Test Setup is a credential with pk, sk, messages, signature
// During Setup, we generate public parameters, secret key, messages, signature
// for our equality tests, we need to set the userid to position 0 of the message vector
pub struct PSUttTestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub keypair: KeyPair<E>,
    pub commitment: Commitment<E>,
    pub signature: PSSignature<E>,
}

impl<E: Pairing> PSUttTestSetup<E> {
    pub fn new(msg_count: usize, user_id: &E::ScalarField) -> Self {
        let mut rng = ark_std::test_rng();
        let context = E::ScalarField::rand(&mut rng);

        let mut messages: Vec<_> = (0..msg_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        messages[0] = *user_id;

        let r = E::ScalarField::rand(&mut rng);

        let pp = PublicParams::<E>::new(&msg_count, &context, &mut rng);
        let keypair = KeyPair::<E>::new(&pp, &mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);
        let signature = PSSignature::sign(&pp, &keypair, &commitment, &mut rng);

        assert!(
            signature.verify(&pp, &keypair, &commitment),
            "sig isn't valid"
        );

        Self {
            pp,
            keypair,
            commitment,
            signature,
        }
    }
}

pub struct BenchmarkSetup<E: Pairing> {
    pub credentials_count: usize,
    pub message_count: usize,
    pub user_id: E::ScalarField,
    pub user_id_blindness: E::ScalarField,
    pub challenge: E::ScalarField,
    pub psutt_setups: Vec<PSUttTestSetup<E>>,
}

impl<E: Pairing> BenchmarkSetup<E> {
    pub fn new(credentials_count: usize, message_count: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let user_id = E::ScalarField::rand(&mut rng);
        let user_id_blindness = E::ScalarField::rand(&mut rng);
        let challenge = E::ScalarField::rand(&mut rng);

        let psutt_setups = (0..credentials_count)
            .map(|_| PSUttTestSetup::new(message_count, &user_id))
            .collect();

        Self {
            credentials_count,
            message_count,
            user_id,
            user_id_blindness,
            challenge,
            psutt_setups,
        }
    }
}

pub struct PSUttImprovedTestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub keypair: KeyPairImproved<E>,
    pub commitment: Commitment<E>,
    pub signature: PSUTTSignatureImproved<E>,
}

impl<E: Pairing> PSUttImprovedTestSetup<E> {
    pub fn new(msg_count: usize, user_id: &E::ScalarField) -> Self {
        let mut rng = ark_std::test_rng();
        let context = E::ScalarField::rand(&mut rng);

        let mut messages: Vec<_> = (0..msg_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        messages[0] = *user_id;

        let r = E::ScalarField::rand(&mut rng);

        let pp = PublicParams::<E>::new(&msg_count, &context, &mut rng);
        let keypair = KeyPairImproved::<E>::new(&pp, &mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);
        let signature = PSUTTSignatureImproved::sign(&pp, &keypair, &commitment, &mut rng);

        assert!(
            signature.verify(&pp, &keypair, &commitment),
            "sig isn't valid"
        );

        Self {
            pp,
            keypair,
            commitment,
            signature,
        }
    }
}

pub struct BenchmarkSetupImproved<E: Pairing> {
    pub credentials_count: usize,
    pub message_count: usize,
    pub user_id: E::ScalarField,
    pub user_id_blindness: E::ScalarField,
    pub challenge: E::ScalarField,
    pub psutt_setups: Vec<PSUttImprovedTestSetup<E>>,
}

impl<E: Pairing> BenchmarkSetupImproved<E> {
    pub fn new(credentials_count: usize, message_count: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let user_id = E::ScalarField::rand(&mut rng);
        let user_id_blindness = E::ScalarField::rand(&mut rng);
        let challenge = E::ScalarField::rand(&mut rng);

        let psutt_setups = (0..credentials_count)
            .map(|_| PSUttImprovedTestSetup::new(message_count, &user_id))
            .collect();

        Self {
            credentials_count,
            message_count,
            user_id,
            user_id_blindness,
            challenge,
            psutt_setups,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::publicparams::PublicParams;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::UniformRand;

    #[test]
    fn test_commitment() {
        let mut rng = ark_std::test_rng();
        let n = 5;
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let g1_comm = g1_commit::<Bls12_381>(&pp, &messages, &r);
        assert!(g1_comm.is_on_curve());

        let g2_comm = g2_commit::<Bls12_381>(&pp, &messages, &r);
        assert!(g2_comm.is_on_curve());

        // check if p1 == p2
        // let p1 = E::pairing()
        let p1 = Bls12_381::pairing(pp.g1, g2_comm);
        let p2 = Bls12_381::pairing(g1_comm, pp.g2);
        assert_eq!(p1, p2, "p1 not eq p2 pairing");
    }

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let msg_count: usize = 10;
        let user_id = Fr::rand(&mut rng);
        let test_setup = PSUttTestSetup::<Bls12_381>::new(msg_count, &user_id);
    }

    #[test]
    fn test_setup_improved() {
        let mut rng = ark_std::test_rng();
        let msg_count: usize = 10;
        let user_id = Fr::rand(&mut rng);
        let test_setup = PSUttImprovedTestSetup::<Bls12_381>::new(msg_count, &user_id);
    }
}
