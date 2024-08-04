use bls12_381::{G2Projective, Scalar, G1Projective, pairing, G2Affine};
use ff::Field;
use rand_chacha::ChaChaRng;


#[derive(Clone, Debug, PartialEq)]
pub struct BBSPlusKey {
    pub x: Scalar,
    pub X: G2Projective,
    pub H: Vec<G1Projective>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BBSPlusSig {
    pub A: G1Projective,
    pub e: Scalar,
    pub s: Scalar,
}

impl BBSPlusKey {
    pub fn keygen(rng: &mut ChaChaRng, l: usize) -> Self {
        let x = Scalar::random(rng.clone());
        let X = G2Projective::generator() * x;

        let mut H: Vec<G1Projective> = Vec::with_capacity(l);

        for _ in 0..=l {
            let tmp = Scalar::random(rng.clone());
            H.push(G1Projective::generator() * tmp);
        }

        Self { x, X, H }
    }
}

impl BBSPlusSig {
    pub fn sign(rng: &mut ChaChaRng, key: &BBSPlusKey, msg: &[Scalar], l: usize) -> Self {
        let e = Scalar::random(rng.clone());
        let s = Scalar::random(rng.clone());
        let mut B = G1Projective::generator();

        for i in 0..l {
            B = B + key.H[i] * msg[i];
        }

        B = B + key.H[l] * s;

        let xeinv = (key.x + e).invert().unwrap();

        let A = B * xeinv;

        Self { A: A.into(), e, s }
    }

    pub fn verify(key: &BBSPlusKey, msg: &[Scalar], l: usize, sig: &BBSPlusSig) {
        let mut B = G1Projective::generator();
        for i in 0..l {
            B = B + key.H[i] * msg[i];
        }
        B = B + key.H[l] * sig.s;

        let p = pairing(
            &sig.A.into(),
            &(key.X + G2Projective::generator() * sig.e).into(),
        );
        let q = pairing(&B.into(), &G2Affine::generator());

        assert_eq!(p, q);
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::SeedableRng;

    use super::*;
    
    #[test]
    fn test_sign() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let l = 10;

        let mut msg: Vec<Scalar> = Vec::with_capacity(l);

        for _ in 0..l {
            let tmp = Scalar::random(rng.clone());
            msg.push(tmp);
        }

        let key = BBSPlusKey::keygen(&mut rng, l);
        let sig = BBSPlusSig::sign(&mut rng, &key, &msg, l);

        BBSPlusSig::verify(&key, &msg, l, &sig);
    }

}