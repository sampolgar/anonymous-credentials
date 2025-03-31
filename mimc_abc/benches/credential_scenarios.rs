use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mimc_abc::{
    credential::{Credential, ShowCredential},
    multi_credential::{AggregatePresentation, CredentialAggregation},
    protocol::MimcAbc,
};

fn benchmark_verification_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("mimc_abc");

    for credential_count in [4, 16, 32].iter() {
        for attribute_count in [4, 16, 32].iter() {
            let id_suffix = format!("{}creds_{}attrs", credential_count, attribute_count);

            group.bench_with_input(
                BenchmarkId::new("non_private_non_batch", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    b.iter_with_setup(
                        || {
                            // Setup code: Initialize system with single issuer
                            let mut rng = ark_std::test_rng();
                            let (protocol, issuer_sk, issuer_vk) =
                                MimcAbc::<Bls12_381>::setup(attr_count, &mut rng);

                            // Create credentials without privacy features
                            let user_id = Fr::rand(&mut rng);
                            let mut credentials = Vec::new();

                            for _ in 0..cred_count {
                                // Create basic credential
                                let mut attributes = vec![user_id]; // First attribute is user ID
                                for _ in 1..attr_count {
                                    attributes.push(Fr::rand(&mut rng));
                                }

                                let r = Fr::rand(&mut rng);
                                let mut credential =
                                    Credential::new(&protocol.ck, &protocol.pp, &attributes, r);

                                // Issue credential
                                let proof = credential.prove_commitment(&protocol.pp, &mut rng);
                                let signature =
                                    protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
                                credential.add_signature(signature);

                                credentials.push(credential);
                            }

                            (protocol, issuer_vk, credentials)
                        },
                        |(protocol, issuer_vk, credentials)| {
                            // Just verify each credential independently
                            for credential in &credentials {
                                black_box(credential.verify(&protocol.pp, &issuer_vk));
                            }
                        },
                    );
                },
            );

            // Add the batch verification benchmark with same parameters
            group.bench_with_input(
                BenchmarkId::new("non_private_with_batch", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    b.iter_with_setup(
                        || {
                            // Setup code (same as non-batch version)
                            let mut rng = ark_std::test_rng();
                            let (protocol, issuer_sk, issuer_vk) =
                                MimcAbc::<Bls12_381>::setup(attr_count, &mut rng);

                            // Create credentials without privacy features
                            let user_id = Fr::rand(&mut rng);
                            let mut credentials = Vec::new();

                            for _ in 0..cred_count {
                                // Create credential as before
                                let mut attributes = vec![user_id];
                                for _ in 1..attr_count {
                                    attributes.push(Fr::rand(&mut rng));
                                }

                                let r = Fr::rand(&mut rng);
                                let mut credential =
                                    Credential::new(&protocol.ck, &protocol.pp, &attributes, r);

                                let proof = credential.prove_commitment(&protocol.pp, &mut rng);
                                let signature =
                                    protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
                                credential.add_signature(signature);

                                credentials.push(credential);
                            }

                            // Create an aggregate presentation
                            let aggregate = CredentialAggregation::aggregate_credentials(
                                &credentials,
                                &protocol.pp,
                                &mut rng,
                            )
                            .unwrap();

                            (protocol, issuer_vk, aggregate)
                        },
                        |(protocol, issuer_vk, aggregate)| {
                            // Use batch verification
                            black_box(aggregate.batch_verify(&protocol.pp, &issuer_vk));
                        },
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, benchmark_verification_methods);
criterion_main!(benches);
