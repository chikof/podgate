//! End to end: requests are admitted through a per-backend limiter, visible on `GET /metrics`.
//! The weighted order and the limit's behaviour are unit tests in `src/fairq.rs`; the load test is
//! `scripts/load-fairness.sh`.

mod common;

use common::{Podgate, Upstream, simple_snapshot};

#[tokio::test]
async fn backend_metrics_report_the_limit() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("hello").await;
    let pushed = podgate
        .push_snapshot(&simple_snapshot(1, &[("a.test", upstream.addr)]))
        .await;
    assert_eq!(pushed.status, 200);

    for _ in 0..5 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!((response.status, response.body.as_str()), (200, "hello"));
    }

    let metrics = podgate.admin_get("/metrics").await.body;
    let backend = upstream.addr;
    assert!(
        metrics.contains(&format!(
            "podgate_backend_limit{{backend=\"{backend}\"}} 32\n"
        )),
        "{metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "podgate_backend_inflight{{backend=\"{backend}\"}} 0\n"
        )),
        "every slot came back: {metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "podgate_backend_waited_total{{backend=\"{backend}\"}} 0\n"
        )),
        "{metrics}"
    );
}
