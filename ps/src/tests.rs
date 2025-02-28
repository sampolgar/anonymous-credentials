// use crate::psproofs::PSProofs;
// use crate::test_helpers::create_ps_test_setup;
// use crate::test_helpers::PSTestSetup;
// use ark_bls12_381::Bls12_381;

// fn setup_test_environment(message_count: usize) -> PSTestSetup<Bls12_381> {
//     create_ps_test_setup::<Bls12_381>(message_count)
// }

// mod multi_attribute {
//     use super::*;

//     #[test]
//     fn test_prove_and_verify_knowledge() {
//         let setup = setup_test_environment(6);
//         let proof = PSProofs::prove_knowledge(&setup);
//         assert!(PSProofs::verify_knowledge(&setup, &proof));
//     }
// }

// mod selective_disclosure {
//     use super::*;

//     #[test]
//     fn test_selective_disclosure() {
//         let setup = setup_test_environment(5);
//         let disclosed_indices = vec![1, 3];
//         let proof = PSProofs::prove_selective_disclosure(&setup, &disclosed_indices)
//             .expect("Proof generation should succeed");
//         let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
//             .expect("Proof verification should complete");
//         assert!(is_valid, "Selective disclosure proof should be valid");
//     }

//     #[test]
//     fn test_invalid_indices() {
//         let setup = setup_test_environment(5);
//         let invalid_indices = vec![5]; // This index is out of bounds
//         let result = PSProofs::prove_selective_disclosure(&setup, &invalid_indices);
//         assert!(
//             result.is_err(),
//             "Proof generation should fail with invalid indices"
//         );
//     }

//     #[test]
//     fn test_disclose_all() {
//         let setup = setup_test_environment(5);
//         let all_indices: Vec<usize> = (0..5).collect();
//         let result = PSProofs::prove_selective_disclosure(&setup, &all_indices);
//         assert!(result.is_ok(), "Should be able to disclose all messages");
//     }

//     #[test]
//     fn test_disclose_none() {
//         let setup = setup_test_environment(5);
//         let no_indices: Vec<usize> = vec![];
//         let proof = PSProofs::prove_selective_disclosure(&setup, &no_indices)
//             .expect("Should be able to generate proof with no disclosed messages");
//         let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
//             .expect("Should be able to verify proof with no disclosed messages");
//         assert!(is_valid, "Proof with no disclosed messages should be valid");
//     }
// }

// mod equality_proof {
//     use super::*;

//     #[test]
//     fn test_equality_proof() {
//         let setup = setup_test_environment(5);
//         // let equality_checks = vec![(1, setup.messages[1]), (3, setup.messages[3])];
//         let equality_checks = vec![(1, setup.messages[1])];
//         let proof = PSProofs::prove_equality(&setup, &equality_checks)
//             .expect("Proof generation should succeed");
//         let is_valid = PSProofs::verify_equality(&setup, &proof, &equality_checks)
//             .expect("Proof verification should complete");
//         assert!(is_valid, "Equality proof should be valid");
//     }
// }
