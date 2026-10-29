use action_runner_controller::cluster::{ClusterRegistry, WorkerCommand};
use action_runner_ipc::{WorkerHeartbeat, WorkerRegistration};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

fn make_worker_reg(node_id: &str, tags: &[&str], max_slots: u32) -> WorkerRegistration {
    WorkerRegistration {
        node_id: node_id.to_string(),
        arch: "riscv64".to_string(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        max_slots,
        ram_total_mb: 32768,
        btrfs_enabled: true,
        toolchains: vec!["system".to_string(), "rust-nightly".to_string()],
    }
}

/// Challenge 1: Rapid alternating requests between exclusive and non-exclusive stages
/// on multi-slot nodes (max_slots = 4 and max_slots = 8).
/// Verifies that exclusive stages never interleave with non-exclusive stages even under rapid switching.
#[tokio::test]
async fn test_challenge_1_rapid_alternating_exclusive_nonexclusive_multi_slot() {
    for max_slots in [4u32, 8u32] {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(64);
        let node_id = format!("worker-multi-{}", max_slots);
        cluster
            .register(make_worker_reg(&node_id, &["k3", "bench"], max_slots), tx)
            .await;

        let req_tags = vec!["bench".to_string()];

        // Run 50 rapid alternating cycles
        for cycle in 0..50 {
            let job_pfx = format!("cycle-{}-s{}", cycle, max_slots);

            // Phase 1: Fill all slots with non-exclusive stages
            for slot in 0..max_slots {
                let stage_id = format!("stage-shared-{}", slot);
                let lease = cluster
                    .lease_slot(&job_pfx, &stage_id, &req_tags, None, false)
                    .await;
                assert!(
                    lease.is_some(),
                    "Cycle {}: Shared slot {}/{} should be granted",
                    cycle,
                    slot + 1,
                    max_slots
                );
            }

            // Phase 2: Over-capacity non-exclusive lease MUST be rejected
            let overflow_lease = cluster
                .lease_slot(&job_pfx, "stage-overflow", &req_tags, None, false)
                .await;
            assert!(
                overflow_lease.is_none(),
                "Cycle {}: Over-capacity request beyond {} slots must return None",
                cycle,
                max_slots
            );

            // Phase 3: Exclusive lease while fully occupied MUST be rejected
            let exc_while_full = cluster
                .lease_slot(&job_pfx, "stage-exclusive-blocked", &req_tags, None, true)
                .await;
            assert!(
                exc_while_full.is_none(),
                "Cycle {}: Exclusive lease while fully occupied ({}/{}) must return None",
                cycle,
                max_slots,
                max_slots
            );

            // Phase 4: Release 1 slot (so max_slots - 1 slots occupied)
            cluster
                .release_stage_slot(&node_id, &job_pfx, "stage-shared-0")
                .await;

            // Exclusive lease while partially occupied MUST STILL be rejected
            let exc_while_partial = cluster
                .lease_slot(&job_pfx, "stage-exclusive-blocked-2", &req_tags, None, true)
                .await;
            assert!(
                exc_while_partial.is_none(),
                "Cycle {}: Exclusive lease while partially occupied ({}/{}) must return None",
                cycle,
                max_slots - 1,
                max_slots
            );

            // Phase 5: Drain all remaining slots
            for slot in 1..max_slots {
                let stage_id = format!("stage-shared-{}", slot);
                cluster
                    .release_stage_slot(&node_id, &job_pfx, &stage_id)
                    .await;
            }

            // Phase 6: Fully drained -> Exclusive lease MUST succeed
            let exc_lease = cluster
                .lease_slot(&job_pfx, "stage-exclusive-active", &req_tags, None, true)
                .await;
            assert!(
                exc_lease.is_some(),
                "Cycle {}: Exclusive lease after full drain must succeed on node with max_slots = {}",
                cycle,
                max_slots
            );

            // Phase 7: While exclusive lease is active, ALL non-exclusive requests MUST be rejected
            for check in 0..max_slots {
                let check_id = format!("stage-blocked-check-{}", check);
                let lease_blocked = cluster
                    .lease_slot(&job_pfx, &check_id, &req_tags, None, false)
                    .await;
                assert!(
                    lease_blocked.is_none(),
                    "Cycle {}: Non-exclusive request {} must be rejected while exclusive lease is held",
                    cycle,
                    check
                );
            }

            // Phase 8: Another exclusive lease MUST also be rejected
            let exc_contention = cluster
                .lease_slot(
                    &job_pfx,
                    "stage-exclusive-contending",
                    &req_tags,
                    None,
                    true,
                )
                .await;
            assert!(
                exc_contention.is_none(),
                "Cycle {}: Second concurrent exclusive lease must be rejected",
                cycle
            );

            // Phase 9: Release exclusive lease
            cluster
                .release_stage_slot(&node_id, &job_pfx, "stage-exclusive-active")
                .await;
        }
    }
}

/// Challenge 2: Attempting to lease while partially full (e.g. 1 of 4, 2 of 4, 3 of 4, 1 of 8, etc.)
/// with exclusive: true MUST be rejected upfront.
#[tokio::test]
async fn test_challenge_2_partial_fill_exclusive_rejection() {
    for max_slots in [4u32, 8u32] {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(64);
        let node_id = format!("worker-partial-{}", max_slots);
        cluster
            .register(make_worker_reg(&node_id, &["k3"], max_slots), tx)
            .await;

        let req_tags = vec!["k3".to_string()];

        // Test every occupancy level from 1 to max_slots
        for occupancy in 1..=max_slots {
            let job_id = format!("job-occ-{}", occupancy);

            // Populate exactly `occupancy` slots
            for s in 0..occupancy {
                let s_id = format!("stg-{}", s);
                let lease = cluster
                    .lease_slot(&job_id, &s_id, &req_tags, None, false)
                    .await;
                assert!(lease.is_some(), "Should grant slot {}/{}", s + 1, occupancy);
            }

            // Verify active_slots matches occupancy
            let views = cluster.list_nodes_view().await;
            let node_view = views.iter().find(|v| v.node_id == node_id).unwrap();
            assert_eq!(
                node_view.active_slots, occupancy,
                "Node active_slots must equal occupancy {}",
                occupancy
            );

            // Attempt exclusive lease from different job -> MUST BE REJECTED
            let lease_diff_job = cluster
                .lease_slot("job-exclusive-diff", "exc-stage", &req_tags, None, true)
                .await;
            assert!(
                lease_diff_job.is_none(),
                "Exclusive lease from different job must be rejected when node has {}/{} slots occupied",
                occupancy,
                max_slots
            );

            // Attempt exclusive lease from SAME job -> MUST BE REJECTED
            let lease_same_job = cluster
                .lease_slot(&job_id, "exc-stage-same", &req_tags, None, true)
                .await;
            assert!(
                lease_same_job.is_none(),
                "Exclusive lease from same job must be rejected when node has {}/{} slots occupied",
                occupancy,
                max_slots
            );

            // Drain all occupied slots
            for s in 0..occupancy {
                let s_id = format!("stg-{}", s);
                cluster.release_stage_slot(&node_id, &job_id, &s_id).await;
            }

            // Verify active_slots is now 0
            let views_drained = cluster.list_nodes_view().await;
            let node_view_drained = views_drained.iter().find(|v| v.node_id == node_id).unwrap();
            assert_eq!(
                node_view_drained.active_slots, 0,
                "Node active_slots must be 0 after drain"
            );

            // Exclusive lease MUST now succeed
            let lease_now = cluster
                .lease_slot(&job_id, "exc-stage-now", &req_tags, None, true)
                .await;
            assert!(
                lease_now.is_some(),
                "Exclusive lease must succeed on drained node (previously {}/{})",
                occupancy,
                max_slots
            );

            // Release exclusive lease
            cluster
                .release_stage_slot(&node_id, &job_id, "exc-stage-now")
                .await;
        }
    }
}

/// Challenge 3: Attempting to lease non-exclusive while exclusive_lease is held
/// MUST be rejected across all slots (even with max_slots = 8).
#[tokio::test]
async fn test_challenge_3_nonexclusive_rejected_while_exclusive_held() {
    for max_slots in [4u32, 8u32] {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(64);
        let node_id = format!("worker-exc-lock-{}", max_slots);
        cluster
            .register(make_worker_reg(&node_id, &["k3"], max_slots), tx)
            .await;

        let req_tags = vec!["k3".to_string()];

        // 1. Acquire exclusive lease
        let exc_lease = cluster
            .lease_slot("job-holder", "stage-bench", &req_tags, None, true)
            .await;
        assert!(
            exc_lease.is_some(),
            "Exclusive lease should succeed on idle node"
        );

        // 2. Attempt 20 non-exclusive requests from different jobs and same job -> ALL MUST RETURN NONE
        for i in 0..20 {
            let job = format!("job-contender-{}", i);
            let stage = format!("stage-contender-{}", i);
            let lease = cluster
                .lease_slot(&job, &stage, &req_tags, None, false)
                .await;
            assert!(
                lease.is_none(),
                "Non-exclusive request {}/20 must be rejected while exclusive lock is held on {}-slot node",
                i + 1,
                max_slots
            );
        }

        // 3. Attempt same job non-exclusive requests -> MUST RETURN NONE
        for i in 0..max_slots {
            let stage = format!("stage-same-job-{}", i);
            let lease = cluster
                .lease_slot("job-holder", &stage, &req_tags, None, false)
                .await;
            assert!(
                lease.is_none(),
                "Same-job non-exclusive request {} must be rejected while exclusive lock is held",
                i
            );
        }

        // 4. In-flight heartbeat reporting active_slots = 0 or active_slots = max_slots
        // must NOT clear or compromise the exclusive lease
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: node_id.clone(),
                active_slots: 0,
                cpu_load_pct: 5.0,
                ram_used_mb: 1024,
                timestamp_epoch_ms: 123456,
            })
            .await;

        // Try leasing non-exclusive again after heartbeat -> MUST STILL BE REJECTED
        let lease_after_hb = cluster
            .lease_slot("job-hb-check", "stage-hb", &req_tags, None, false)
            .await;
        assert!(
            lease_after_hb.is_none(),
            "Heartbeat with active_slots: 0 must not clobber exclusive lock"
        );

        // 5. Release the exclusive lease
        cluster
            .release_stage_slot(&node_id, "job-holder", "stage-bench")
            .await;

        // 6. Verify all max_slots can now be leased non-exclusively
        for s in 0..max_slots {
            let stage = format!("stage-post-exc-{}", s);
            let lease = cluster
                .lease_slot("job-unblocked", &stage, &req_tags, None, false)
                .await;
            assert!(
                lease.is_some(),
                "Slot {}/{} should be leasable after exclusive lock release",
                s + 1,
                max_slots
            );
        }
    }
}

/// Challenge 4: Concurrent cancellation during an exclusive lease
/// must immediately free the node for normal dispatches.
#[tokio::test]
async fn test_challenge_4_concurrent_cancellation_during_exclusive_lease() {
    let cluster = ClusterRegistry::new();
    let (tx, mut rx) = mpsc::channel(64);
    let node_id = "worker-cancel-test";
    let max_slots = 8u32;

    cluster
        .register(make_worker_reg(node_id, &["k3", "bench"], max_slots), tx)
        .await;

    let req_tags = vec!["bench".to_string()];

    // Part A: Acquire exclusive lease
    let exc_lease = cluster
        .lease_slot("job-to-cancel", "stage-exclusive", &req_tags, None, true)
        .await;
    assert!(exc_lease.is_some());

    // Verify node is locked
    assert!(cluster
        .lease_slot("job-other", "stage-blocked", &req_tags, None, false)
        .await
        .is_none());

    // Cancel a DIFFERENT job -> exclusive lease on job-to-cancel must REMAIN INTACT
    cluster
        .cancel_and_release_job_slots("job-other-irrelevant", "Cancelled")
        .await;
    assert!(
        cluster
            .lease_slot("job-other", "stage-blocked-2", &req_tags, None, false)
            .await
            .is_none(),
        "Cancelling an unrelated job must not unlock job-to-cancel's exclusive lease"
    );

    // Cancel job-to-cancel
    cluster
        .cancel_and_release_job_slots("job-to-cancel", "Pipeline aborted by user")
        .await;

    // Verify cancellation command arrived on worker command channel
    let received_cmd = rx.try_recv();
    assert!(
        received_cmd.is_ok(),
        "Worker command channel must receive cancellation task"
    );
    if let Ok(WorkerCommand::Cancel(task)) = received_cmd {
        assert_eq!(task.job_id, "job-to-cancel");
        assert_eq!(task.stage_id, "stage-exclusive");
        assert_eq!(task.reason, "Pipeline aborted by user");
    } else {
        panic!("Expected WorkerCommand::Cancel");
    }

    // Node must immediately be leasable for new exclusive lease
    let exc_next = cluster
        .lease_slot("job-next", "stage-next-exc", &req_tags, None, true)
        .await;
    assert!(
        exc_next.is_some(),
        "Node must immediately accept new exclusive lease after cancellation"
    );

    // Release exc_next
    cluster
        .release_stage_slot(node_id, "job-next", "stage-next-exc")
        .await;

    // Part B: Multi-job multi-slot cancellation on max_slots = 8
    // Job 1 leases 4 slots, Job 2 leases 4 slots
    for i in 0..4 {
        let l1 = cluster
            .lease_slot("job-1", &format!("stg-{}", i), &req_tags, None, false)
            .await;
        assert!(l1.is_some());
    }
    for i in 0..4 {
        let l2 = cluster
            .lease_slot("job-2", &format!("stg-{}", i), &req_tags, None, false)
            .await;
        assert!(l2.is_some());
    }

    // Node is at 8/8 capacity. Cancel Job 1.
    cluster
        .cancel_and_release_job_slots("job-1", "Job 1 cancelled")
        .await;

    // Now 4 slots are freed (Job 2 remains active with 4 slots).
    // Exclusive lease MUST be rejected (Job 2 is still running!)
    let exc_blocked = cluster
        .lease_slot("job-3", "stage-bench", &req_tags, None, true)
        .await;
    assert!(
        exc_blocked.is_none(),
        "Exclusive lease must be rejected while Job 2 is still occupying 4 slots"
    );

    // Non-exclusive lease can take 4 more slots (up to 8)
    for i in 0..4 {
        let l3 = cluster
            .lease_slot("job-4", &format!("stg-{}", i), &req_tags, None, false)
            .await;
        assert!(
            l3.is_some(),
            "Non-exclusive lease should occupy newly freed slots"
        );
    }

    // Cancel Job 2 and Job 4 -> Node is now completely free
    cluster
        .cancel_and_release_job_slots("job-2", "Job 2 complete/cancelled")
        .await;
    cluster
        .cancel_and_release_job_slots("job-4", "Job 4 complete/cancelled")
        .await;

    // Exclusive lease MUST now succeed
    let exc_freed = cluster
        .lease_slot("job-5", "stage-bench-final", &req_tags, None, true)
        .await;
    assert!(
        exc_freed.is_some(),
        "Node must be fully leasable exclusively after all jobs cancelled"
    );
}

/// Challenge 5: Worker disconnect / heartbeat timeout while holding exclusive lease
/// must free state upon unregister/timeout.
#[tokio::test]
async fn test_challenge_5_worker_disconnect_and_heartbeat_timeout() {
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(64);
    let node_id = "worker-disconnect-test";
    let max_slots = 8u32;

    cluster
        .register(
            make_worker_reg(node_id, &["k3", "bench"], max_slots),
            tx.clone(),
        )
        .await;

    let req_tags = vec!["bench".to_string()];

    // 1. Lease exclusive stage
    let exc_lease = cluster
        .lease_slot("job-disc", "stage-exc", &req_tags, None, true)
        .await;
    assert!(exc_lease.is_some());

    // 2. Worker disconnects (tunnel teardown calls unregister)
    cluster.unregister(node_id).await;

    // 3. While unregistered, node is completely absent from registry
    assert!(
        !cluster.is_node_online(node_id).await,
        "Unregistered node must report offline"
    );
    let lease_while_gone = cluster
        .lease_slot("job-new", "stage-new", &req_tags, None, false)
        .await;
    assert!(
        lease_while_gone.is_none(),
        "Cannot lease from unregistered node"
    );

    // 4. Worker reconnects with fresh registration
    cluster
        .register(make_worker_reg(node_id, &["k3", "bench"], max_slots), tx)
        .await;

    // 5. Node is online and has ZERO stale leases or exclusive locks
    assert!(
        cluster.is_node_online(node_id).await,
        "Reconnected node must report online"
    );
    let views = cluster.list_nodes_view().await;
    let view = views.iter().find(|v| v.node_id == node_id).unwrap();
    assert_eq!(
        view.active_slots, 0,
        "Reconnected node must have 0 active slots"
    );

    // 6. Node accepts new exclusive lease immediately
    let exc_reconnect = cluster
        .lease_slot("job-reconnected", "stage-bench", &req_tags, None, true)
        .await;
    assert!(
        exc_reconnect.is_some(),
        "Reconnected worker node should accept exclusive lease immediately"
    );

    // Release exclusive lease
    cluster
        .release_stage_slot(node_id, "job-reconnected", "stage-bench")
        .await;

    // 7. Part B: Heartbeat timeout (>15 seconds)
    // Lease an exclusive stage
    let exc_lease_2 = cluster
        .lease_slot("job-timeout", "stage-bench-timeout", &req_tags, None, true)
        .await;
    assert!(exc_lease_2.is_some());

    // Initially online
    assert!(cluster.is_node_online(node_id).await);

    // Sleep for 16 seconds to trigger the 15-second heartbeat expiration
    println!("Testing wall-clock heartbeat timeout (waiting 16s)...");
    sleep(Duration::from_secs(16)).await;

    // After 16 seconds without heartbeat, is_node_online MUST return false
    assert!(
        !cluster.is_node_online(node_id).await,
        "Node must be declared offline after 16s without heartbeat"
    );

    // lease_slot MUST reject scheduling on the offline node
    let lease_offline = cluster
        .lease_slot("job-try-offline", "stage-x", &req_tags, None, false)
        .await;
    assert!(
        lease_offline.is_none(),
        "lease_slot must skip node whose heartbeat is older than 15s"
    );

    // Scheduler watchdog detects node is offline and releases the stage slot
    cluster
        .release_stage_slot(node_id, "job-timeout", "stage-bench-timeout")
        .await;

    // When worker resumes sending heartbeats, it recovers
    cluster
        .heartbeat(WorkerHeartbeat {
            node_id: node_id.to_string(),
            active_slots: 0,
            cpu_load_pct: 1.0,
            ram_used_mb: 512,
            timestamp_epoch_ms: 1234567,
        })
        .await;

    assert!(
        cluster.is_node_online(node_id).await,
        "Node must be online after sending fresh heartbeat"
    );

    // Node is completely clean and can lease new stages
    let lease_resumed = cluster
        .lease_slot("job-resumed", "stage-bench-resumed", &req_tags, None, true)
        .await;
    assert!(
        lease_resumed.is_some(),
        "Node must accept leases cleanly after watchdog release and fresh heartbeat"
    );
}

/// Challenge 6: High-concurrency stress test with continuous invariant verification.
/// Spawns 40 concurrent tokio tasks (20 exclusive, 20 shared) on an 8-slot node.
/// Invariant: An exclusive stage must NEVER run concurrently with ANY other stage.
#[tokio::test]
async fn test_challenge_6_concurrent_stress_and_invariant_verification() {
    let cluster = Arc::new(ClusterRegistry::new());
    let (tx, _rx) = mpsc::channel(256);
    let node_id = "worker-stress-invariants";
    let max_slots = 8u32;

    cluster
        .register(make_worker_reg(node_id, &["k3", "perf"], max_slots), tx)
        .await;

    let req_tags = vec!["perf".to_string()];
    let invariant_violated = Arc::new(AtomicBool::new(false));
    let completed_leases = Arc::new(AtomicU32::new(0));
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Background invariant monitor: inspects cluster state every 1ms
    let monitor_cluster = Arc::clone(&cluster);
    let monitor_violated = Arc::clone(&invariant_violated);
    let monitor_stop = Arc::clone(&stop_signal);

    let monitor_handle = tokio::spawn(async move {
        while !monitor_stop.load(Ordering::Relaxed) {
            let views = monitor_cluster.list_nodes_view().await;
            if let Some(v) = views.iter().find(|n| n.node_id == node_id) {
                // If active_slots > max_slots -> VIOLATION
                if v.active_slots > max_slots {
                    monitor_violated.store(true, Ordering::SeqCst);
                    eprintln!(
                        "INVARIANT VIOLATION: active_slots ({}) > max_slots ({})",
                        v.active_slots, max_slots
                    );
                }
            }
            sleep(Duration::from_millis(1)).await;
        }
    });

    let mut handles = Vec::new();
    let start_time = std::time::Instant::now();
    let duration_limit = Duration::from_millis(1500);

    // Spawn 20 tasks requesting exclusive leases
    for task_idx in 0..20 {
        let c = Arc::clone(&cluster);
        let tags = req_tags.clone();
        let counter = Arc::clone(&completed_leases);
        let violated = Arc::clone(&invariant_violated);

        handles.push(tokio::spawn(async move {
            let mut iter = 0;
            while start_time.elapsed() < duration_limit && iter < 100 {
                iter += 1;
                let job_id = format!("job-exc-{}-{}", task_idx, iter);
                let stage_id = "exclusive-stage";

                if let Some((_, _)) = c.lease_slot(&job_id, stage_id, &tags, None, true).await {
                    // Holding exclusive lease: verify active_slots is exactly 1!
                    let views = c.list_nodes_view().await;
                    if let Some(v) = views.iter().find(|n| n.node_id == node_id) {
                        if v.active_slots != 1 {
                            violated.store(true, Ordering::SeqCst);
                            eprintln!("INVARIANT VIOLATION: exclusive stage running but active_slots is {}", v.active_slots);
                        }
                    }

                    // Hold for a short duration
                    sleep(Duration::from_millis(2)).await;

                    // Release exclusive lease
                    c.release_stage_slot(node_id, &job_id, stage_id).await;
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                sleep(Duration::from_millis(2)).await;
            }
        }));
    }

    // Spawn 20 tasks requesting non-exclusive leases
    for task_idx in 0..20 {
        let c = Arc::clone(&cluster);
        let tags = req_tags.clone();
        let counter = Arc::clone(&completed_leases);

        handles.push(tokio::spawn(async move {
            let mut iter = 0;
            while start_time.elapsed() < duration_limit && iter < 100 {
                iter += 1;
                let job_id = format!("job-shared-{}-{}", task_idx, iter);
                let stage_id = format!("shared-stage-{}", iter);

                if let Some((_, _)) = c.lease_slot(&job_id, &stage_id, &tags, None, false).await {
                    // Hold for a short duration
                    sleep(Duration::from_millis(2)).await;

                    // Release shared lease
                    c.release_stage_slot(node_id, &job_id, &stage_id).await;
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                sleep(Duration::from_millis(2)).await;
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    stop_signal.store(true, Ordering::Relaxed);
    monitor_handle.await.unwrap();

    assert!(
        !invariant_violated.load(Ordering::SeqCst),
        "Safety invariant violated during high-concurrency stress test!"
    );

    let total_completed = completed_leases.load(Ordering::Relaxed);
    println!(
        "Completed {} leases without a single invariant violation",
        total_completed
    );
    assert!(
        total_completed >= 50,
        "Expected substantial concurrency throughput, got {}",
        total_completed
    );

    // Verify node is completely drained at conclusion
    let final_views = cluster.list_nodes_view().await;
    let final_view = final_views.iter().find(|n| n.node_id == node_id).unwrap();
    assert_eq!(
        final_view.active_slots, 0,
        "All slots must be released at end of test"
    );
}

/// Challenge 7: False and mismatched release calls must never release an active exclusive lock.
#[tokio::test]
async fn test_challenge_7_adversarial_mismatched_release() {
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(64);
    let node_id = "worker-mismatched-release";

    cluster
        .register(make_worker_reg(node_id, &["k3"], 4), tx)
        .await;

    let req_tags = vec!["k3".to_string()];

    // Lease exclusive stage
    let lease = cluster
        .lease_slot("job-target", "stage-bench", &req_tags, None, true)
        .await;
    assert!(lease.is_some());

    // 1. Release with wrong node_id -> lock must remain held
    cluster
        .release_stage_slot("wrong-node-id", "job-target", "stage-bench")
        .await;
    assert!(cluster
        .lease_slot("job-new", "stage-x", &req_tags, None, false)
        .await
        .is_none());

    // 2. Release with wrong job_id -> lock must remain held
    cluster
        .release_stage_slot(node_id, "wrong-job-id", "stage-bench")
        .await;
    assert!(cluster
        .lease_slot("job-new", "stage-x", &req_tags, None, false)
        .await
        .is_none());

    // 3. Release with wrong stage_id -> lock must remain held
    cluster
        .release_stage_slot(node_id, "job-target", "wrong-stage-id")
        .await;
    assert!(cluster
        .lease_slot("job-new", "stage-x", &req_tags, None, false)
        .await
        .is_none());

    // 4. Release with empty strings -> lock must remain held
    cluster.release_stage_slot(node_id, "", "").await;
    assert!(cluster
        .lease_slot("job-new", "stage-x", &req_tags, None, false)
        .await
        .is_none());

    // 5. Correct release -> lock MUST be freed
    cluster
        .release_stage_slot(node_id, "job-target", "stage-bench")
        .await;
    assert!(
        cluster
            .lease_slot("job-new", "stage-x", &req_tags, None, false)
            .await
            .is_some(),
        "Valid release must unlock the node"
    );
}

/// Challenge 8: Multi-node drain and exclusivity routing.
/// When multiple nodes exist with varying occupancies, an exclusive stage
/// must pick ONLY completely idle nodes, and non-exclusive stages must bypass exclusive nodes.
#[tokio::test]
async fn test_challenge_8_multi_node_drain_and_exclusivity_routing() {
    let cluster = ClusterRegistry::new();
    let (tx1, _rx1) = mpsc::channel(64);
    let (tx2, _rx2) = mpsc::channel(64);
    let (tx3, _rx3) = mpsc::channel(64);

    // Node 1: max_slots = 4, tagged with ["k3", "node1"]
    cluster
        .register(make_worker_reg("node-1-busy", &["k3", "node1"], 4), tx1)
        .await;
    // Node 2: max_slots = 8, tagged with ["k3", "node2"]
    cluster
        .register(
            make_worker_reg("node-2-semi-busy", &["k3", "node2"], 8),
            tx2,
        )
        .await;
    // Node 3: max_slots = 4 (completely idle), tagged with ["k3", "node3"]
    cluster
        .register(make_worker_reg("node-3-idle", &["k3", "node3"], 4), tx3)
        .await;

    // Occupy 2 slots explicitly on node-1 via its specific tag
    let l1_1 = cluster
        .lease_slot("j1", "s1", &["node1".to_string()], None, false)
        .await;
    assert!(l1_1.is_some());
    assert_eq!(l1_1.unwrap().0, "node-1-busy");

    let l1_2 = cluster
        .lease_slot("j1", "s2", &["node1".to_string()], None, false)
        .await;
    assert!(l1_2.is_some());
    assert_eq!(l1_2.unwrap().0, "node-1-busy");

    // Occupy 1 slot explicitly on node-2 via its specific tag
    let l2_1 = cluster
        .lease_slot("j2", "s1", &["node2".to_string()], None, false)
        .await;
    assert!(l2_1.is_some());
    assert_eq!(l2_1.unwrap().0, "node-2-semi-busy");

    // Request an exclusive stage requiring "k3" ->
    // Node 1 has 2 slots occupied -> rejected
    // Node 2 has 1 slot occupied -> rejected
    // Node 3 has 0 slots occupied -> MUST BE CHOSEN!
    let req_k3 = vec!["k3".to_string()];
    let exc_lease = cluster
        .lease_slot("job-bench", "bench-stage", &req_k3, None, true)
        .await;
    assert!(
        exc_lease.is_some(),
        "Exclusive lease must be granted on idle node"
    );
    assert_eq!(
        exc_lease.unwrap().0,
        "node-3-idle",
        "Exclusive lease must route to the only 0-occupancy node (node-3-idle)"
    );

    // Request second exclusive stage requiring "k3" -> all 3 nodes ineligible! Must return None
    let exc_lease_2 = cluster
        .lease_slot("job-bench-2", "bench-stage-2", &req_k3, None, true)
        .await;
    assert!(
        exc_lease_2.is_none(),
        "Second exclusive lease must return None (node-1 & node-2 are occupied, node-3 is exclusive)"
    );

    // Request non-exclusive stage requiring "k3" -> MUST route to node-1 or node-2, NEVER to node-3
    let non_exc_lease = cluster
        .lease_slot("job-shared", "shared-stage", &req_k3, None, false)
        .await;
    assert!(non_exc_lease.is_some());
    let chosen_node = non_exc_lease.unwrap().0;
    assert!(
        chosen_node == "node-1-busy" || chosen_node == "node-2-semi-busy",
        "Non-exclusive lease must route to node-1 or node-2, not exclusive node-3 (got {})",
        chosen_node
    );
}
