use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use wist_core::{sampling, vrf};

fn vrf_prove(c: &mut Criterion) {
    let sk = [7u8; 32];
    let alpha = [9u8; 32];
    c.bench_function("vrf_prove_and_hash", |b| {
        b.iter(|| {
            let pi = vrf::prove(black_box(&sk), black_box(&alpha)).unwrap();
            vrf::proof_to_hash(&pi).unwrap()
        })
    });
}

fn draw_select(c: &mut Criterion) {
    let beta = [3u8; 64];
    let id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    c.bench_function("draw_and_select", |b| {
        b.iter(|| {
            let d = sampling::draw(black_box(&beta), black_box(id));
            sampling::selected(d, 200_000)
        })
    });
}

criterion_group!(benches, vrf_prove, draw_select);
criterion_main!(benches);
