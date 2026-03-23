//! Multipath circuit management: primary/backup circuits per destination.
//!
//! A `CircuitGroup` holds one primary and zero or more backup circuits to the
//! same destination peer. The primary carries all traffic; backups carry only
//! keepalive padding. On primary failure, the best backup is promoted instantly.
//!
//! Three path modes:
//! - **Direct**: A direct link exists to the peer. Data goes over the link;
//!   the circuit group serves purely as a hot standby for when the link dies.
//! - **Routed**: No direct link, but the peer is known (PeerId). Circuits are
//!   built through the overlay with path diversity (different first hops).
//! - **Hidden**: Destination is a hidden service. Circuits go through
//!   rendezvous points; the group manages redundancy across rendezvous paths.

use std::collections::HashMap;
use std::time::Instant;

use crate::types::PeerId;

/// How the group reaches the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    /// Direct link exists — use link as primary transport, circuits as backup.
    Direct,
    /// No direct link — circuits through the overlay.
    Routed,
    /// Hidden service via rendezvous.
    Hidden,
}

/// Role of a circuit within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitRole {
    Primary,
    Backup,
}

/// A circuit path entry within a group.
#[derive(Debug, Clone)]
pub struct CircuitPath {
    pub circuit_id: u32,
    pub role: CircuitRole,
    /// First hop of this circuit (for path diversity checking).
    pub first_hop: PeerId,
    /// Full path of the circuit.
    pub path: Vec<PeerId>,
    /// When this circuit was added to the group.
    pub added_at: Instant,
}

/// Manages multiple circuits to a single destination with primary/backup failover.
#[derive(Debug)]
pub struct CircuitGroup {
    /// The destination peer (or rendezvous peer for hidden services).
    pub destination: PeerId,
    /// How we reach this destination.
    pub mode: PathMode,
    /// Circuits in this group (primary first, then backups).
    circuits: Vec<CircuitPath>,
}

impl CircuitGroup {
    /// Create a new group with a primary circuit.
    pub fn new(
        destination: PeerId,
        mode: PathMode,
        primary_circuit_id: u32,
        first_hop: PeerId,
        path: Vec<PeerId>,
    ) -> Self {
        Self {
            destination,
            mode,
            circuits: vec![CircuitPath {
                circuit_id: primary_circuit_id,
                role: CircuitRole::Primary,
                first_hop,
                path,
                added_at: Instant::now(),
            }],
        }
    }

    /// Get the primary circuit ID, if one exists.
    pub fn primary(&self) -> Option<u32> {
        self.circuits
            .iter()
            .find(|c| c.role == CircuitRole::Primary)
            .map(|c| c.circuit_id)
    }

    /// Get all backup circuit IDs.
    pub fn backups(&self) -> Vec<u32> {
        self.circuits
            .iter()
            .filter(|c| c.role == CircuitRole::Backup)
            .map(|c| c.circuit_id)
            .collect()
    }

    /// All circuit IDs in this group.
    pub fn all_circuit_ids(&self) -> Vec<u32> {
        self.circuits.iter().map(|c| c.circuit_id).collect()
    }

    /// Add a backup circuit. Returns false if the path shares intermediate nodes
    /// with the primary (not node-disjoint), but still adds it as a weak backup.
    pub fn add_backup(&mut self, circuit_id: u32, first_hop: PeerId, path: Vec<PeerId>) -> bool {
        let disjoint = self.is_node_disjoint(&path);
        self.circuits.push(CircuitPath {
            circuit_id,
            role: CircuitRole::Backup,
            first_hop,
            path,
            added_at: Instant::now(),
        });
        disjoint
    }

    /// Remove a circuit from the group (e.g., when destroyed).
    /// Returns the role it had, or None if not found.
    pub fn remove_circuit(&mut self, circuit_id: u32) -> Option<CircuitRole> {
        if let Some(pos) = self
            .circuits
            .iter()
            .position(|c| c.circuit_id == circuit_id)
        {
            let removed = self.circuits.remove(pos);
            Some(removed.role)
        } else {
            None
        }
    }

    /// Promote the best backup to primary. Returns the new primary circuit_id,
    /// or None if no backups exist.
    pub fn promote_backup(&mut self) -> Option<u32> {
        // Find the first backup
        if let Some(backup) = self
            .circuits
            .iter_mut()
            .find(|c| c.role == CircuitRole::Backup)
        {
            backup.role = CircuitRole::Primary;
            Some(backup.circuit_id)
        } else {
            None
        }
    }

    /// Handle primary circuit death: remove it and promote a backup.
    /// Returns (old_primary_id, new_primary_id_or_none).
    pub fn handle_primary_death(&mut self, dead_circuit_id: u32) -> (u32, Option<u32>) {
        self.remove_circuit(dead_circuit_id);
        let new_primary = self.promote_backup();
        (dead_circuit_id, new_primary)
    }

    /// Check if a path is node-disjoint from the primary circuit.
    /// Ignores the destination itself (which must be shared).
    fn is_node_disjoint(&self, candidate_path: &[PeerId]) -> bool {
        if let Some(primary) = self
            .circuits
            .iter()
            .find(|c| c.role == CircuitRole::Primary)
        {
            // Intermediate nodes are all except the last (destination).
            let primary_intermediates: std::collections::HashSet<_> = primary
                .path
                .iter()
                .take(primary.path.len().saturating_sub(1))
                .collect();
            let candidate_intermediates: Vec<_> = candidate_path
                .iter()
                .take(candidate_path.len().saturating_sub(1))
                .collect();
            !candidate_intermediates
                .iter()
                .any(|p| primary_intermediates.contains(p))
        } else {
            true // No primary, can't conflict
        }
    }

    /// Get first hops already used by circuits in this group (for diversity).
    pub fn used_first_hops(&self) -> Vec<PeerId> {
        self.circuits.iter().map(|c| c.first_hop).collect()
    }

    /// Whether this group has any circuits at all.
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Whether this group has a backup ready.
    pub fn has_backup(&self) -> bool {
        self.circuits.iter().any(|c| c.role == CircuitRole::Backup)
    }
}

/// Maps destination peers to their circuit groups.
pub struct CircuitGroupTable {
    groups: HashMap<PeerId, CircuitGroup>,
}

impl CircuitGroupTable {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Insert a new group for a destination. Replaces any existing group.
    pub fn insert(&mut self, group: CircuitGroup) {
        self.groups.insert(group.destination, group);
    }

    /// Look up a group by destination.
    pub fn get(&self, dest: &PeerId) -> Option<&CircuitGroup> {
        self.groups.get(dest)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, dest: &PeerId) -> Option<&mut CircuitGroup> {
        self.groups.get_mut(dest)
    }

    /// Find which group (if any) contains a given circuit_id.
    pub fn find_by_circuit(&self, circuit_id: u32) -> Option<&CircuitGroup> {
        self.groups
            .values()
            .find(|g| g.all_circuit_ids().contains(&circuit_id))
    }

    /// Mutable version of find_by_circuit.
    pub fn find_by_circuit_mut(&mut self, circuit_id: u32) -> Option<&mut CircuitGroup> {
        self.groups
            .values_mut()
            .find(|g| g.all_circuit_ids().contains(&circuit_id))
    }

    /// Remove a group by destination.
    pub fn remove(&mut self, dest: &PeerId) -> Option<CircuitGroup> {
        self.groups.remove(dest)
    }

    /// Remove empty groups (no circuits remaining).
    pub fn gc(&mut self) {
        self.groups.retain(|_, g| !g.is_empty());
    }

    /// All groups.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &CircuitGroup)> {
        self.groups.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn basic_group_lifecycle() {
        let mut group =
            CircuitGroup::new(pid(10), PathMode::Routed, 1, pid(2), vec![pid(2), pid(10)]);
        assert_eq!(group.primary(), Some(1));
        assert!(group.backups().is_empty());
        assert!(!group.has_backup());

        // Add backup through different first hop
        let disjoint = group.add_backup(2, pid(3), vec![pid(3), pid(10)]);
        assert!(disjoint);
        assert!(group.has_backup());
        assert_eq!(group.backups(), vec![2]);

        // Kill primary
        let (old, new) = group.handle_primary_death(1);
        assert_eq!(old, 1);
        assert_eq!(new, Some(2));
        assert_eq!(group.primary(), Some(2));
        assert!(!group.has_backup());
    }

    #[test]
    fn node_disjointness_detection() {
        // Primary: pid(2) → pid(5) → pid(10)
        let mut group = CircuitGroup::new(
            pid(10),
            PathMode::Routed,
            1,
            pid(2),
            vec![pid(2), pid(5), pid(10)],
        );

        // Backup shares pid(5) — NOT disjoint
        let disjoint = group.add_backup(2, pid(3), vec![pid(3), pid(5), pid(10)]);
        assert!(!disjoint);

        // Backup through pid(6) — disjoint
        let mut group2 = CircuitGroup::new(
            pid(10),
            PathMode::Routed,
            1,
            pid(2),
            vec![pid(2), pid(5), pid(10)],
        );
        let disjoint = group2.add_backup(3, pid(3), vec![pid(3), pid(6), pid(10)]);
        assert!(disjoint);
    }

    #[test]
    fn group_table_find_by_circuit() {
        let mut table = CircuitGroupTable::new();
        let mut group =
            CircuitGroup::new(pid(10), PathMode::Routed, 1, pid(2), vec![pid(2), pid(10)]);
        group.add_backup(2, pid(3), vec![pid(3), pid(10)]);
        table.insert(group);

        assert!(table.find_by_circuit(1).is_some());
        assert!(table.find_by_circuit(2).is_some());
        assert!(table.find_by_circuit(99).is_none());
    }

    #[test]
    fn no_primary_after_all_dead() {
        let mut group =
            CircuitGroup::new(pid(10), PathMode::Routed, 1, pid(2), vec![pid(2), pid(10)]);
        let (_, new) = group.handle_primary_death(1);
        assert_eq!(new, None);
        assert!(group.is_empty());
    }

    #[test]
    fn used_first_hops() {
        let mut group =
            CircuitGroup::new(pid(10), PathMode::Routed, 1, pid(2), vec![pid(2), pid(10)]);
        group.add_backup(2, pid(3), vec![pid(3), pid(10)]);
        let hops = group.used_first_hops();
        assert_eq!(hops.len(), 2);
        assert!(hops.contains(&pid(2)));
        assert!(hops.contains(&pid(3)));
    }
}
