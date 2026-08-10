use wist_bench::scenario::Scenario;
use wist_bench::sim;

#[test]
fn golden_tiny_scenario_is_pinned() {
    let mut sc = Scenario::tier("small").unwrap();
    sc.pages = 100_000;
    sc.churn_bp = 100;
    sc.blocks_per_day = 2;
    sc.days = 2;
    sc.auditors = 1;
    sc.seed = "golden-v1".into();
    let r = sim::run(&sc);
    assert_eq!(r.selected, vec![vec![45, 46]]);
}
