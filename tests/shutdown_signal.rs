use coreshift_core::signal::{install_shutdown_flag, shutdown_requested};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

#[test]
#[ignore = "sends SIGINT to the current process"]
fn test_sigint_sets_shutdown_flag() {
    SHUTDOWN_FLAG.store(false, Ordering::Release);
    install_shutdown_flag(&SHUTDOWN_FLAG).unwrap();

    let ret = unsafe { libc::kill(libc::getpid(), libc::SIGINT) };
    assert_eq!(ret, 0);

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if shutdown_requested(&SHUTDOWN_FLAG) {
            return;
        }
        std::thread::yield_now();
    }

    panic!("shutdown flag was not set by SIGINT");
}
