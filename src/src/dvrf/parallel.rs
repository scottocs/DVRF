//! Bounded local parallelism with deterministic result ordering.
pub(crate) fn map<T: Sync, U: Send, F: Fn(usize, &T) -> U + Sync>(
    items: &[T],
    workers: usize,
    f: F,
) -> Vec<U> {
    assert!(workers > 0);
    if workers == 1 || items.len() <= 1 {
        return items.iter().enumerate().map(|(i, x)| f(i, x)).collect();
    }
    let chunk = items.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let jobs: Vec<_> = items
            .chunks(chunk)
            .enumerate()
            .map(|(part, values)| {
                let f = &f;
                scope.spawn(move || {
                    values
                        .iter()
                        .enumerate()
                        .map(|(i, x)| f(part * chunk + i, x))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        jobs.into_iter()
            .flat_map(|job| job.join().expect("DVRF worker panicked"))
            .collect()
    })
}
