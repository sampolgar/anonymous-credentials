use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_std::ops::{Add, Mul};

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
}
