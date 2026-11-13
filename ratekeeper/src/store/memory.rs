use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ratekeeper::{
    algorithms::{gcra::Gcra, sliding_window::SlidingWindow, token_bucket::TokenBucket},
    clock::MockClock,
    store::memory::MemoryStore,
    Policy, RateLimiter,
};
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_gcra_single_key(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let limiter = rt.block_on(async {
        RateLimiter::new(
            Gcra::new(Policy::new(1_000_000, Duration::from_secs(1))),
            MemoryStore::for_window(100_000, Duration::from_secs(2)),
            MockClock::new(0),
        )
    });

    let mut group = c.benchmark_group("gcra");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_key", |b| {
        b.to_async(&rt).iter(|| limiter.check(b"bench-key"))
    });
    group.finish();
}

fn bench_gcra_many_keys(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let limiter = rt.block_on(async {
        RateLimiter::new(
            Gcra::new(Policy::new(1_000_000, Duration::from_secs(1))),
            MemoryStore::for_window(100_000, Duration::from_secs(2)),
            MockClock::new(0),
        )
    });

    let mut group = c.benchmark_group("gcra");
    group.throughput(Throughput::Elements(1));
    for n_keys in [10u64, 100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("many_keys", n_keys), &n_keys, |b, &k| {
            let keys: Vec<Vec<u8>> = (0..k).map(|n| n.to_string().into_bytes()).collect();
            let mut i = 0usize;
            b.to_async(&rt).iter(|| {
                let key = &keys[i];
                i = (i + 1) % keys.len();
                limiter.check(key)
            });
        });
    }
    group.finish();
}

fn bench_token_bucket_single_key(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let limiter = rt.block_on(async {
        RateLimiter::new(
            TokenBucket::new(Policy::new(1_000_000, Duration::from_secs(1))),
            MemoryStore::for_window(100_000, Duration::from_secs(2)),
            MockClock::new(0),
        )
    });

    let mut group = c.benchmark_group("token_bucket");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_key", |b| {
        b.to_async(&rt).iter(|| limiter.check(b"bench-key"))
    });
    group.finish();
}

fn bench_sliding_window_single_key(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let limiter = rt.block_on(async {
        RateLimiter::new(
            SlidingWindow::new(Policy::new(1_000_000, Duration::from_secs(1))),
            MemoryStore::for_window(100_000, Duration::from_secs(2)),
            MockClock::new(0),
        )
    });

    let mut group = c.benchmark_group("sliding_window");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_key", |b| {
        b.to_async(&rt).iter(|| limiter.check(b"bench-key"))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_gcra_single_key,
    bench_gcra_many_keys,
    bench_token_bucket_single_key,
    bench_sliding_window_single_key,
);
criterion_main!(benches);


