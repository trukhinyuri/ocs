import Contract

namespace OCS.Core

theorem admission_exact (g : Grant) : admits g = true ↔ allowed g := by
  simp [admits, allowed, Bool.and_eq_true, and_assoc]

theorem missing_authority_refuses (g : Grant) (invalid : ¬ allowed g) : admits g = false := by
  cases h : admits g with
  | false => rfl
  | true => exact False.elim (invalid ((admission_exact g).mp h))

theorem successful_grant : admits ⟨true, true, true, true, true, true⟩ = true := rfl
theorem denied_grant : admits ⟨true, true, true, true, false, true⟩ = false := rfl

theorem all_required (required optional : List Bool) :
    eligible required optional = true ↔ ∀ r ∈ required, r = true := by
  simp [eligible, conditional]

theorem optional_independent (req a b : List Bool) : eligible req a = eligible req b := rfl

theorem display_independent (a b : String) (issuer rev : Nat) :
    identityForDisplay a issuer rev = identityForDisplay b issuer rev := rfl

theorem preserve_on_failure (old : Publication) (next : Nat) (verified admitted : Bool)
    (reject : (verified && admitted) = false) : publish old next verified admitted = old := by
  simp [publish, reject]

theorem install_valid (old : Publication) (next : Nat) :
    (publish old next true true).active = some next := rfl

theorem arbitrary_failed_updates (old : Publication) (updates : List (Nat × Bool × Bool))
    (rejected : ∀ u ∈ updates, (u.2.1 && u.2.2) = false) : replayUpdates old updates = old := by
  induction updates generalizing old with
  | nil => rfl
  | cons u tail ih =>
    have hu := rejected u (List.mem_cons_self ..)
    have ht : ∀ x ∈ tail, (x.2.1 && x.2.2) = false := by
      intro x hx
      exact rejected x (List.mem_cons_of_mem _ hx)
    simpa [replayUpdates, List.foldl_cons, preserve_on_failure old u.1 u.2.1 u.2.2 hu]
      using ih old ht

theorem deadlines_decrease (initial : Nat) (hops : List Nat) :
    throughHops initial hops ≤ initial := by
  induction hops generalizing initial with
  | nil => exact Nat.le_refl _
  | cons h tail ih => exact Nat.le_trans (ih (bound initial h)) (Nat.min_le_left ..)

theorem step_conserves (s : Resources) (e : Event) : occupancy (advance s e) = occupancy s := by
  cases s with
  | mk a b =>
    cases e <;> cases a <;> cases b <;> simp [advance, occupancy] <;> omega

theorem capacity_invariant (s : Resources) (trace : List Event) :
    occupancy (history s trace) = occupancy s := by
  induction trace generalizing s with
  | nil => rfl
  | cons h t ih => exact (ih (advance s h)).trans (step_conserves s h)

theorem busy_bound (limit : Nat) (trace : List Event) :
    (history ⟨limit, 0⟩ trace).serving ≤ limit := by
  have h := capacity_invariant ⟨limit,0⟩ trace
  simp [occupancy] at h
  omega

theorem zero_capacity_denies (busy : Nat) : advance ⟨0,busy⟩ .admit = ⟨0,busy⟩ := rfl
theorem capacity_progress (free busy : Nat) : (advance ⟨free+1,busy⟩ .admit).serving = busy+1 := rfl

theorem hard_requires_bound (p a r i : Bool) (q : Option Nat) (budget : Nat) :
    nativeAdmission p a r i .hard q budget = true ↔
      p = true ∧ a = true ∧ r = true ∧ i = true ∧ ∃ n, q = some n ∧ 0 < n ∧ n ≤ budget := by
  cases q <;> simp [nativeAdmission, Bool.and_eq_true, and_assoc]

theorem native_soft_witness : nativeAdmission true true true true .soft none 0 = true := rfl
theorem native_hard_refusal : nativeAdmission true true true true .hard none 100 = false := rfl
theorem unknown_on_lost_evidence : reobserve .unresolved none = .unresolved := rfl

theorem transitive_refinement {α β : Type} (a b c : VersionedContract α β)
    (ab : Refines a b) (bc : Refines b c) : Refines a c := by
  constructor
  · intro x hx
    exact ab.1 x (bc.1 x hx)
  · intro x y hx hxy
    exact bc.2 x y hx (ab.2 x y (bc.1 x hx) hxy)

theorem status_realizable : Realizable statusContract := by
  exact ⟨id, fun _ h => ⟨h, rfl⟩⟩
theorem valid_status_witness : statusContract.inputs 0 ∧ statusContract.results 0 0 := by simp [statusContract]
theorem wrong_status_forbidden : ¬ statusContract.results 0 1 := by simp [statusContract]

theorem rank_decreases_on_path {edge : Nat → Nat → Prop} (rank : Nat → Nat)
    (decreasing : ∀ a b, edge a b → rank b < rank a) {a b} (path : Path edge a b) :
    rank b < rank a := by
  induction path with
  | single h => exact decreasing _ _ h
  | next _ h ih => exact Nat.lt_trans (decreasing _ _ h) ih

theorem rank_excludes_cycle {edge : Nat → Nat → Prop} (rank : Nat → Nat)
    (decreasing : ∀ a b, edge a b → rank b < rank a) (a : Nat) : ¬ Path edge a a := by
  intro cycle
  exact (Nat.lt_irrefl _) (rank_decreases_on_path rank decreasing cycle)

theorem forward_preserves_optional {α : Type} (known extra : List α) :
    (forwardOptional known extra).drop known.length = extra := by simp [forwardOptional]

theorem no_evidence_no_action (grant : Bool) : actionable false grant = false := rfl
theorem public_record_noninterference (record : TraceRecord) (a b : String) :
    publicRecord record a = publicRecord record b := rfl

theorem identity_disjoint (a b : Nat) : Identity.account a ≠ Identity.operation b := by simp
theorem reverse_is_unbound (e : Edge) (distinct : e.caller ≠ e.receiver) :
    routes e e.receiver e.caller e.resource = false := by
  simp [routes, Ne.symm distinct]
theorem bound_route_exists (e : Edge) : routes e e.caller e.receiver e.resource = true := by simp [routes]
theorem no_grant_from_request (g : Grant) (inactive : g.effect = false) :
    byPermissionRequest g true = false := by simp [byPermissionRequest, admits, inactive]
theorem elapsed_does_not_rollback (state : Outcome) (elapsed : Nat) :
    afterDeadline state elapsed = state := rfl

theorem fresh_grant_required (before now : Grant) (h : ¬ allowed now) :
    atEffect before now = false := missing_authority_refuses now h

theorem extension_preserves_status : Refines extendedStatus statusContract := by
  constructor
  · intro x h
    change x = 0 at h
    change x ≤ 1
    omega
  · intro x y hx hy
    exact ⟨hx, hy.2⟩

theorem extended_status_realizable : Realizable extendedStatus :=
  ⟨id, fun _ h => ⟨h, rfl⟩⟩

end OCS.Core
