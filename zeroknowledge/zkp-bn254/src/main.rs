// Ref: Buchanan, William J (2023). Zero-knowledge proof using crypto pairing. Asecuritysite.com. https://asecuritysite.com/rust/rust_miracl03
extern crate rand_core;

use mcore::bn254::big;
use mcore::bn254::ecp;
use mcore::bn254::ecp2;
use mcore::bn254::fp2;
use mcore::bn254::pair;
use mcore::bn254::rom;
use mcore::rand::{RAND_impl, RAND};
use std::env;

fn main() {
    println!("ZKP using bn254 pairing");

    let G1 = ecp::ECP::generator();
    let G2 = ecp2::ECP2::generator();

    let args: Vec<String> = env::args().collect();

    let mut x: isize = 7;
    let mut a: isize = -1;
    let mut b: isize = -42;

    if args.len() > 1 {
        x = args[1].parse().unwrap();
    }
    if args.len() > 2 {
        a = args[2].parse().unwrap();
    }
    if args.len() > 3 {
        b = args[3].parse().unwrap();
    }

    println!("Solution proposed = {}", x);

    //Equation is x^2 + ax + b = 0

    let mut xbig = mcore::bn254::big::BIG::new_int(isize::abs(x));
    let mut xG1 = pair::g1mul(&G1, &xbig);
    let mut xG2 = pair::g2mul(&G2, &xbig);
    if (x < 0) {
        xG1.neg();
        xG2.neg();
    }

    let mut abig = mcore::bn254::big::BIG::new_int(isize::abs(a));
    let mut xGa = pair::g2mul(&G2, &abig);
    if (a < 0) {
        xGa.neg();
    }

    let mut bbig = mcore::bn254::big::BIG::new_int(isize::abs(b));
    let mut xGb = pair::g2mul(&G2, &bbig);
    if (b < 0) {
        xGb.neg();
    }

    if (b < 0 && a < 0) {
        println!("\nEqn: x^2 - {} x - {}\n", isize::abs(a), isize::abs(b));
    } else if (b < 0) {
        println!("\nEqn: x^2 + {} x + {}\n", a, isize::abs(b));
    } else if (a < 0) {
        println!("\nEqn: x^2 + {} x + {}\n", isize::abs(a), b);
    } else {
        println!("\nEqn: x^2 + {} x + {}\n", a, b);
    }

    println!("\nxG1: {}", xG1.to_string());
    println!("\nxG2: {}", xG2.to_string());
    println!("\nxGa: {}", xGa.to_string());
    println!("\nxGb: {}", xGb.to_string());

    let mut p1 = pair::ate(&xG2, &xG1);
    p1 = pair::fexp(&p1);
    let mut p2 = pair::ate(&xGa, &xG1);
    p2 = pair::fexp(&p2);
    let mut p3 = pair::ate(&xGb, &G1);
    p3 = pair::fexp(&p3);

    p1.mul(&p2);
    p1.mul(&p3);

    if (p1.isunity()) {
        println!("SUCCESS - challenge x is solution to equation");
    } else {
        println!("FAILURE - challenge x is not solution to equation");
    }

    // xG1: (03264DCCFF0E7C8DE83D9BAA1BC15615E93C3D8E13755F21D45CFC62911993B0,0B4DDF7264812FFDE94BD4359C7DC035AADE884795E828D71B5CBF3C1054BA2E)

    // xG2: ([08CA1AC367CF4DC0A1B75066FA911AA896956BA89246C5F3C25094FC0F0D7AB2,1ED25C11E74CEAD06A7BAA51FC41F0E6085B4CB26F5735416F12237953C792A2],
    //   [19E12AF084B06ED6DBDED38695D6DBA7AA05F62250835346B9574309B35DCFEA,1CAE33085867FE051412632C8CC4229B3FB65E617FE975C07D2482688F4AE826])

    // xGa: ([061A10BB519EB62FEB8D8C7E8C61EDB6A4648BBB4898BF0D91EE4224C803FB2B,0516AAF9BA737833310AA78C5982AA5B1F4D746BAE3784B70D8C34C1E7D54CF3],
    //   [230ACCE1D4506CBE1FA36CE996737DE53763F5194241F6568D0F1F876E32D479,16683973C374EADB2AC709290A0C72D0B090F90028C636BC1CD2E51394C53178])

    // xGb: ([02347E5C2F0802A05E43267FE89DE3DEDC77D64556B495610913E6A767DB7871,079078E9427F50798E62C1F804562A9326760F5D94F0A4206DD149D3F037D680],
    //   [0D250F7544EE22BC914C8D902B0A18C8A8613543217C01A07A3E73B380DDF93F,0C7CDECC7B14C33886D39FD4275F079C6A2D1639DC582262F231EECE38B1987B])
}
