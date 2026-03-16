use crate::models::{FileEventRecord, ProcessInfo};
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ExecutionNode {
    pub process: ProcessInfo,
    pub last_seen: DateTime<Utc>,
    pub children: Vec<i32>,
    pub related_paths: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionGraphSnapshot {
    pub nodes: HashMap<i32, ExecutionNode>,
}

#[derive(Debug, Clone)]
pub struct ExecutionChain {
    pub chain_root_pid: i32,
    pub chain_root_command: String,
    pub pids: Vec<i32>,
    pub process_chain: Vec<ProcessInfo>,
    pub related_paths: Vec<String>,
    pub attack_chain_length: usize,
}

#[derive(Debug, Clone)]
pub struct ExecutionGraphCache {
    nodes: HashMap<i32, ExecutionNode>,
    max_age_seconds: i64,
}

impl ExecutionGraphCache {
    pub fn new(max_age_seconds: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            max_age_seconds,
        }
    }

    pub fn ingest_processes(
        &mut self,
        processes: &[ProcessInfo],
        recent_file_events: &[FileEventRecord],
        now: DateTime<Utc>,
    ) {
        self.prune(now);

        for process in processes {
            let related_paths = related_paths_for_process(process, recent_file_events, now);

            let entry = self
                .nodes
                .entry(process.pid)
                .or_insert_with(|| ExecutionNode {
                    process: process.clone(),
                    last_seen: now,
                    children: Vec::new(),
                    related_paths: Vec::new(),
                });

            entry.process = process.clone();
            entry.last_seen = now;

            for path in related_paths {
                push_unique(&mut entry.related_paths, path);
            }

            if process.ppid > 0 {
                let parent = self.nodes.entry(process.ppid).or_insert_with(|| ExecutionNode {
                    process: ProcessInfo::placeholder(process.ppid),
                    last_seen: now,
                    children: Vec::new(),
                    related_paths: Vec::new(),
                });

                push_unique_i32(&mut parent.children, process.pid);
            }
        }
    }

    pub fn snapshot(&self) -> ExecutionGraphSnapshot {
        ExecutionGraphSnapshot {
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

impl ExecutionGraphSnapshot {
    pub fn chain_for_pid(&self, pid: i32, max_depth: usize) -> Option<ExecutionChain> {
        let start = self.nodes.get(&pid)?;
        let root_pid = self.find_root_pid(pid, max_depth);
        let root = self.nodes.get(&root_pid).unwrap_or(start);

        let mut visited = HashSet::new();
        let mut ordered_pids = Vec::new();
        self.collect_descendants(root_pid, max_depth, &mut visited, &mut ordered_pids);

        if ordered_pids.is_empty() {
            ordered_pids.push(pid);
        }

        let mut process_chain = Vec::new();
        let mut related_paths = Vec::new();

        for current_pid in &ordered_pids {
            if let Some(node) = self.nodes.get(current_pid) {
                process_chain.push(node.process.clone());
                for path in &node.related_paths {
                    push_unique(&mut related_paths, path.clone());
                }
                for path in &node.process.behavior.referenced_paths {
                    push_unique(&mut related_paths, path.clone());
                }
            }
        }

        Some(ExecutionChain {
            chain_root_pid: root_pid,
            chain_root_command: root.process.command.clone(),
            pids: ordered_pids.clone(),
            process_chain,
            related_paths,
            attack_chain_length: ordered_pids.len(),
        })
    }

    fn find_root_pid(&self, pid: i32, max_depth: usize) -> i32 {
        let mut current_pid = pid;
        let mut remaining = max_depth;

        while remaining > 0 {
            let Some(node) = self.nodes.get(&current_pid) else {
                break;
            };

            if node.process.ppid <= 0 || !self.nodes.contains_key(&node.process.ppid) {
                break;
            }

            current_pid = node.process.ppid;
            remaining -= 1;
        }

        current_pid
    }

    fn collect_descendants(
        &self,
        pid: i32,
        max_depth: usize,
        visited: &mut HashSet<i32>,
        ordered_pids: &mut Vec<i32>,
    ) {
        if max_depth == 0 || !visited.insert(pid) {
            return;
        }

        ordered_pids.push(pid);

        if let Some(node) = self.nodes.get(&pid) {
            for child_pid in &node.children {
                self.collect_descendants(*child_pid, max_depth - 1, visited, ordered_pids);
            }
        }
    }
}

fn related_paths_for_process(
    process: &ProcessInfo,
    recent_file_events: &[FileEventRecord],
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut related = Vec::new();
    let process_text = format!("{} {}", process.command, process.args);

    for path in &process.behavior.referenced_paths {
        push_unique(&mut related, path.clone());
    }

    for file_event in recent_file_events {
        if now.signed_duration_since(file_event.timestamp).num_seconds() > 180 {
            continue;
        }

        if process_text.contains(&file_event.path) {
            push_unique(&mut related, file_event.path.clone());
        }
    }

    related
}

fn push_unique(target: &mut Vec<String>, value: String) {
    if !target.iter().any(|existing| existing == &value) {
        target.push(value);
    }
}

fn push_unique_i32(target: &mut Vec<i32>, value: i32) {
    if !target.iter().any(|existing| existing == &value) {
        target.push(value);
    }
}