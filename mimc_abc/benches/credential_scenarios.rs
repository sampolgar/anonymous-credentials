use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mimc_abc::{
    credential::{Credential, ShowCredential},
    multi_credential::{AggregatePresentation, CredentialAggregation, PlaintextAggregation},
    protocol::MimcAbc,
    public_params::PublicParams,
    signature::VerificationKey,
};

fn benchmark_verification_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("mimc_abc");

    for credential_count in [4, 16, 32].iter() {
        for attribute_count in [4, 16, 32].iter() {
            let id_suffix = format!("{}creds_{}attrs", credential_count, attribute_count);

            // First benchmark (non_private_non_batch) is already correct since it directly uses credential.verify()
            // Fix the non-private non-batch benchmark
            group.bench_with_input(
                BenchmarkId::new("non_private_non_batch", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    // Setup code OUTSIDE benchmark
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
                        let signature = protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
                        credential.add_signature(signature);

                        credentials.push(credential);
                    }

                    // NOW we benchmark ONLY the verification
                    b.iter(|| {
                        // Just verify each credential independently
                        for credential in &credentials {
                            black_box(credential.verify(&protocol.pp, &issuer_vk));
                        }
                    });
                },
            );

            // Fix the non-private with batch benchmark
            group.bench_with_input(
                BenchmarkId::new("non_private_with_batch", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    // Setup code OUTSIDE benchmark
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
                        let signature = protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
                        credential.add_signature(signature);

                        credentials.push(credential);
                    }

                    // Create a plaintext aggregation for batch verification
                    let plaintext_aggregate = PlaintextAggregation::new(credentials);

                    // NOW we benchmark ONLY the verification
                    b.iter(|| {
                        // Use batch verification
                        black_box(plaintext_aggregate.batch_verify(&protocol.pp, &issuer_vk))
                    });
                },
            );

            // Multi-issuer multi-credential verification with identity binding
            group.bench_with_input(
                BenchmarkId::new("multi_issuer_identity_binding", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    // Setup code OUTSIDE benchmark
                    let mut rng = ark_std::test_rng();

                    // Create one issuer per credential for simplicity (or use any number you prefer)
                    let issuer_count = cred_count.min(8); // Could be any number

                    // Create vectors to store issuers' data
                    let mut protocols = Vec::new();
                    let mut issuer_sks = Vec::new();
                    let mut issuer_vks = Vec::new();

                    for _ in 0..issuer_count {
                        let (protocol, issuer_sk, issuer_vk) =
                            MimcAbc::<Bls12_381>::setup(attr_count, &mut rng);
                        protocols.push(protocol);
                        issuer_sks.push(issuer_sk);
                        issuer_vks.push(issuer_vk);
                    }

                    // Create credentials with same user ID across issuers
                    let user_id = Fr::rand(&mut rng);
                    let mut all_credentials = Vec::new();
                    let mut credential_to_issuer = Vec::new();

                    // Create credentials distributed across issuers
                    for i in 0..cred_count {
                        let issuer_idx = i % issuer_count;

                        // Create credential with user_id
                        let mut attributes = vec![user_id];
                        for _ in 1..attr_count {
                            attributes.push(Fr::rand(&mut rng));
                        }

                        let r = Fr::rand(&mut rng);
                        let mut credential = Credential::new(
                            &protocols[issuer_idx].ck,
                            &protocols[issuer_idx].pp,
                            &attributes,
                            r,
                        );

                        // Issue credential
                        let proof =
                            credential.prove_commitment(&protocols[issuer_idx].pp, &mut rng);
                        let signature = protocols[issuer_idx]
                            .issue(&proof, &issuer_sks[issuer_idx], &mut rng)
                            .unwrap();
                        credential.add_signature(signature);

                        // Simple verification check
                        assert!(
                            credential.verify(&protocols[issuer_idx].pp, &issuer_vks[issuer_idx]),
                            "Credential verification failed"
                        );

                        all_credentials.push(credential);
                        credential_to_issuer.push(issuer_idx);
                    }

                    // Create credential references
                    let cred_refs: Vec<&Credential<Bls12_381>> = all_credentials.iter().collect();

                    // Create public parameter references in the same order as credentials
                    let pp_refs: Vec<&PublicParams<Bls12_381>> = credential_to_issuer
                        .iter()
                        .map(|&idx| &protocols[idx].pp)
                        .collect();

                    // Create the linked presentation
                    let linked_presentation =
                        mimc_abc::linked_credentials::LinkedCredentialPresentation::create(
                            &cred_refs, &pp_refs, &mut rng,
                        )
                        .unwrap();

                    // Get verification key references in the same order
                    let vk_refs: Vec<&VerificationKey<Bls12_381>> = credential_to_issuer
                        .iter()
                        .map(|&idx| &issuer_vks[idx])
                        .collect();

                    // Validate that the linked presentation works before benchmarking
                    assert!(
                        linked_presentation.verify(&pp_refs, &vk_refs).unwrap(),
                        "Linked presentation verification failed"
                    );

                    // NOW we benchmark ONLY the verification
                    b.iter(|| black_box(linked_presentation.verify(&pp_refs, &vk_refs).unwrap()));
                },
            );

            // Multi-credential batch verification (single issuer with batch optimizations)
            group.bench_with_input(
                BenchmarkId::new("multi_credential_batch_verify", &id_suffix),
                &(*credential_count, *attribute_count),
                |b, &(cred_count, attr_count)| {
                    // Setup code for single issuer - OUTSIDE benchmark
                    let mut rng = ark_std::test_rng();
                    let (protocol, issuer_sk, issuer_vk) =
                        MimcAbc::<Bls12_381>::setup(attr_count, &mut rng);

                    // Create credentials with privacy features
                    let user_id = Fr::rand(&mut rng);
                    let mut credentials = Vec::new();

                    for _ in 0..cred_count {
                        // Create credential
                        let mut attributes = vec![user_id];
                        for _ in 1..attr_count {
                            attributes.push(Fr::rand(&mut rng));
                        }

                        let r = Fr::rand(&mut rng);
                        let mut credential =
                            Credential::new(&protocol.ck, &protocol.pp, &attributes, r);

                        // Issue credential
                        let proof = credential.prove_commitment(&protocol.pp, &mut rng);
                        let signature = protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
                        credential.add_signature(signature);

                        credentials.push(credential);
                    }

                    // Create an aggregate presentation - still part of setup
                    let aggregate = CredentialAggregation::aggregate_credentials(
                        &credentials,
                        &protocol.pp,
                        &mut rng,
                    )
                    .unwrap();

                    // NOW we benchmark ONLY the verification
                    b.iter(|| {
                        // Use batch verification with privacy features
                        black_box(aggregate.batch_verify(&protocol.pp, &issuer_vk))
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, benchmark_verification_methods);
criterion_main!(benches);
