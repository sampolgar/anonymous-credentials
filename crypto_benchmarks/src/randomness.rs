#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::Rng;
    use ark_std::test_rng;

    // 1. Function using a generic type <R: Rng>
    /// Generates a random u32 using a generic RNG that implements the Rng trait.
    fn generate_generic<R: Rng>(rng: &mut R) -> u32 {
        rng.gen()
    }

    #[test]
    fn test_generic_rng() {
        // Create two separate RNG instances
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        // Generate values using the generic function
        let val1 = generate_generic(&mut rng1);
        let val2 = generate_generic(&mut rng2);
        // Since test_rng is deterministic and each instance starts from the same seed,
        // the first values should be equal
        assert_eq!(val1, val2, "Values should be equal with separate RNGs");
    }

    // 2. Function using &mut impl Rng
    /// Generates a random u32 using a mutable reference to an RNG implementing the Rng trait.
    fn generate_impl(rng: &mut impl Rng) -> u32 {
        rng.gen()
    }

    #[test]
    fn test_impl_rng() {
        // Create two separate RNG instances
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        // Generate values using the impl function
        let val1 = generate_impl(&mut rng1);
        let val2 = generate_impl(&mut rng2);
        // Since test_rng is deterministic, the first values from separate instances should match
        assert_eq!(val1, val2, "Values should be equal with separate RNGs");
    }

    // 3. Test passing &mut rng to a function
    #[test]
    fn test_pass_rng() {
        // Create a single RNG instance
        let mut rng = test_rng();
        // Generate two values using the same RNG instance
        let val1 = generate_impl(&mut rng);
        let val2 = generate_impl(&mut rng);
        // Since it's the same RNG, the state advances, and values should be different
        assert_ne!(val1, val2, "Values should be different with the same RNG");
    }

    // 4. Function creating RNG inside
    /// Generates a random u32 by creating a test_rng instance inside the function.
    fn generate_inside() -> u32 {
        let mut rng = test_rng();
        rng.gen()
    }

    #[test]
    fn test_inside_rng() {
        // Call the function twice, each time creating a new RNG
        let val1 = generate_inside();
        let val2 = generate_inside();
        // Since each call creates a new test_rng with the same starting seed,
        // the values should be equal
        assert_eq!(val1, val2, "Values should be equal with new RNGs each time");
    }
}
