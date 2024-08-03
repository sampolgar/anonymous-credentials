simple understanding referencing
keygen(&message_count); calls a function, passes a reference to the message_count
keygen(message_count); calls a function, passes a copy of the message_count

let y = message_count assigns message_count to y. message_count needs to be the value and not a reference
let y = \*message_count assigns y the value of the reference message_count

fn(message_count: usize) takes a copy of a data type usize and names it message_count
fn(message_count: &usize) takes a reference of a usize and names it message_count

Dereferencing vector doesn't give ownership of the vector,
let g1_points = ECMulPairs::new(&pk.y_g1); // vector of y_g1 points
let dosomething = \*points //dereferencing &Vec<T> gives us a [T] (a slice), not a Vec<T>

SimplePairs::new(pk.y_g1.clone(), sk_ym.clone()) vs SimplePairs::new(pk.y_g1, sk_ym)
pk.y_g1.clone() copies vectors, pk.y_g1 transfers ownership

## Unwrap()

- extracts values inside types
-

let pairing_miller_loop = E::multi_miller_loop(&[&a, &c], &[&b, &d]);

&&<E as ark_ec::pairing::Pairing>::G1Prepared: std::convert::Into<<E as ark_ec::pairing::Pairing>::G1Prepared>
The double reference &&

std::convert::Into = convert into is not satisfied
Trying to convert something with double reference.

How to know which to provide?

Function signature shows it wants a copy of the values

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

explain thihs
impl<P: Bls12Config> Pairing for Bls12<P>

fn scalars([E::ScalarField], Vec<E::ScalarField>){}
What's the difference?
[E::ScalarField] = fixed size array determined at compile time
Vec<E::ScalarField> = dynamic size array

Group vs CurveGroup

pub trait VectorECMul: Group {}

impl<T: Group> VectorECMul for T {}

Vs

pub trait VectorECMul: CurveGroup {}
impl<T: CurveGroup> VectorECMul for T {}

What's dif between T: CurveGroup and T: Group:
CurveGroup extends Group with specific EC functionality including specific EC operations
Group supports affine & projective, not dependent

There's a difference in how ScalarField type is defined in Group and CurveGroup
Group type has associated type ScalarField. We can use Self::ScalarField to refer to the scalar field type

CurveGroup inherits from Group but redefines ScalarField as <Self as Group>::ScalarField.

let zi: Vec<Fr> = alpha_blindings
.iter()
.zip(messages.iter())
.map(|(alpha, message)| alpha + challenge2 \* \*message)
.collect();

Solution = using into_iter() and dereferencing.
What does into_iter() do differently?

    let zi: Vec<Fr> = alpha_blindings
        .into_iter()
        .zip(messages.iter())
        .map(|(alpha, message)| alpha + challenge2 * *message) // Dereference message
        .collect();

expects a slice of references to tuples, but we're providing a vector of owned tuples
expected reference `&[(&ark_ec::short_weierstrass::Affine<ark_bls12_381::g1::Config>, &ark_ec::short_weierstrass::Affine<ark_bls12_381::g2::Config>)]`
found reference `&std::vec::Vec<(ark_ec::short_weierstrass::Affine<ark_bls12_381::g1::Config>, ark_ec::short_weierstrass::Affine<ark_bls12_381::g2::Config>)>`

before
let mut lhs_pairs = vec![(sigma_prime_1, pk.g2.mul(z_beta).into_affine())];

after
let lhs_pairs: Vec<(&G1Affine, &G2Affine)> = vec![
    (&sigma_prime_1, &pk.g2.mul(z_beta).into_affine())
];

change
define Vec<(&G1Affine, &G2Affine)>

let y_g1 = E::G1::normalize_batch(&y_g1);




a value of type `std::vec::Vec<<G as ark_ec::CurveGroup>::Affine>` cannot be built from an iterator over elements of type `G`
the trait `std::iter::FromIterator<G>` is not implemented for `std::vec::Vec<<G as ark_ec::CurveGroup>::Affine>`

An iterator in Rust is an object that allows you to traverse a sequence of elements. It's a trait that provides methods to access elements one by one.
The collect() method is used to transform an iterator into a collection (like a Vec).
In our case, we're trying to collect a sequence of G (which are projective points) into a Vec<G::Affine> (which is a vector of affine points). This is causing the type mismatch.