;use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct CommitmentKey<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub g1_y: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    pub g2_y: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
}

pub struct PublicParams<E: Pairing> {
    pub ck: CommitmentKey<E>,
    pub vk: E::G2Affine,
}

pub struct SignerKey<E: Pairing> {
    pub sk: E::ScalarField,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new<R: Rng>(m_count: &usize, rng: &mut R) -> (Self, SignerKey<E>) {
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    let yi: Vec<E::ScalarField> = (0..*m_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    let g1_y_proj: Vec<E::G1> = yi
        .iter()
        .map(|yi| g1.mul(*yi))
        .collect();
    let g1_y = E::G1::normalize_batch(&g1_y_proj);

    let g2_y_proj: Vec<E::G2> = yi
        .iter()
        .map(|yi| g2.mul(*yi))
        .collect();
    let g2_y = E::G2::normalize_batch(&g2_y_proj);

    // generate secret x
    let x = E::ScalarField::rand(rng);
    let sk = g1.mul(x).into_affine();
    let vk = g2.mul(x).into_affine();

    SignerKey{
        sk,
    },

    PublicParams {
        ck: CommitmentKey {
            g1,
            g2,
            g1_y,
            g2_y,
        },
        vk,
    }
    (Self, SignerKey)
}

pub struct Commitment<E: Pairing> {
    pub m: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub cm: (E::G1Affine, E::G2Affine),
}

impl<E: Pairing> Commitment<E> {
    fn new(m: Vec<E::ScalarField>, r: E::ScalarField, params: &PublicParams<E>) -> Self {}
}
