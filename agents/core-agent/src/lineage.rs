use crate::classify::is_browser_command;
use crate::models::ProcessInfo;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct LineageNode {
    pub process: ProcessInfo,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub children: Vec<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct LineageSnapshot {
    pub nodes: HashMap<i32, LineageNode>,
}

#[derive(Debug, Clone)]
pub struct ProcessLineageCache {
    nodes: HashMap<i32, LineageNode>,
    max_age_seconds: i64,
}

impl ProcessLineageCache {
    pub fn new(max_age_seconds: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            max_age_seconds,
        }
    }

    pub fn ingest_processes(&mut self, processes: &[ProcessInfo], now: DateTime<Utc>) {
        self.prune(now);

        for process in processes {
            let entry = self.nodes.entry(process.pid).or_insert_with(|| LineageNode {
                process: process.clone(),
                first_seen: now,
                last_seen: now,
                children: Vec::new(),
            });

            entry.process = process.clone();
            entry.last_seen = now;

            if process.ppid > 0 {
                let parent = self.nodes.entry(process.ppid).or_insert_with(|| LineageNode {
                    process: ProcessInfo::placeholder(process.ppid),
                    first_seen: now,
                    last_seen: now,
                    children: Vec::new(),
                });

                push_unique_i32(&mut parent.children, process.pid);
            }
        }
    }

    pub fn snapshot(&self) -> LineageSnapshot {
        LineageSnapshot {
            nodes: self.nodes.clone(),
        }
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.max_age_seconds);
        self.nodes.retain(|_, node| node.last_seen >= cutoff);

        let live_pids: HashSet<i32> = self.nodes.keys().copied().collect();
        for node in self.nodes.values_mut() {
            node.children.retain(|pid| live_pids.contains(pid));
        }
    }
}

impl LineageSnapshot {
    pub fn ancestor_chain_for_pid(&self, pid: i32, max_depth: usize) -> Vec<ProcessInfo> {
        let mut chain = Vec::new();
        let mut current_pid = pid;
        let mut remaining = max_depth;

        while remaining > 0 {
            let Some(node) = self.nodes.get(&current_pid) else {
                break;
            };

            if node.process.ppid <= 0 {
                break;
            }

            let Some(parent_node) = self.nodes.get(&node.process.ppid) else {
                break;
            };

            chain.push(parent_node.process.clone());
            current_pid = parent_node.process.pid;
            remaining -= 1;
        }

        chain
    }

    pub fn lineage_depth_for_pid(&self, pid: i32, max_depth: usize) -> usize {
        self.ancestor_chain_for_pid(pid, max_depth).len()
    }

    pub fn has_browser_ancestor(&self, pid: i32, max_depth: usize) -> bool {
        self.ancestor_chain_for_pid(pid, max_depth)
            .iter()
            .any(|process| is_browser_command(&process.command))
    }

    pub fn nearest_browser_ancestor_command(&self, pid: i32, max_depth: usize) -> Option<String> {
        self.ancestor_chain_for_pid(pid, max_depth)
            .into_iter()
            .find(|process| is_browser_command(&process.command))
            .map(|process| process.command)
    }

    pub fn descendant_count_for_pid(&self, pid: i32, max_depth: usize) -> usize {
        let mut visited = HashSet::new();
        self.collect_descendants(pid, max_depth, &mut visited);
        visited.len().saturating_sub(1)
    }

    fn collect_descendants(&self, pid: i32, max_depth: usize, visited: &mut HashSet<i32>) {
        if max_depth == 0 || !visited.insert(pid) {
            return;
        }

        if let Some(node) = self.nodes.get(&pid) {
            for child_pid in &node.children {
                self.collect_descendants(*child_pid, max_depth - 1, visited);
            }
        }
    }
}

fn push_unique_i32(target: &mut Vec<i32>, value: i32) {
    if !target.iter().any(|existing| existing == &value) {
        target.push(value);
    }
}