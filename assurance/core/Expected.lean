import Proofs

namespace OCS.Core

-- Frozen obligations checked against the submitted proof terms.
example (g : Grant) : admits g = true ↔ allowed g := by
  apply admission_exact <;> assumption
#print axioms OCS.Core.admission_exact

example (g : Grant) (invalid : ¬ allowed g) : admits g = false := by
  apply missing_authority_refuses <;> assumption
#print axioms OCS.Core.missing_authority_refuses

example : admits ⟨true, true, true, true, true, true⟩ = true := by
  apply successful_grant <;> assumption
#print axioms OCS.Core.successful_grant

example : admits ⟨true, true, true, true, false, true⟩ = false := by
  apply denied_grant <;> assumption
#print axioms OCS.Core.denied_grant

example (required optional : List Bool) :
    eligible required optional = true ↔ ∀ r ∈ required, r = true := by
  apply all_required <;> assumption
#print axioms OCS.Core.all_required

example (req a b : List Bool) : eligible req a = eligible req b := by
  apply optional_independent <;> assumption
#print axioms OCS.Core.optional_independent

example (a b : String) (issuer rev : Nat) :
    identityForDisplay a issuer rev = identityForDisplay b issuer rev := by
  apply display_independent <;> assumption
#print axioms OCS.Core.display_independent

example (old : Publication) (next : Nat) (verified admitted : Bool)
    (reject : (verified && admitted) = false) : publish old next verified admitted = old := by
  apply preserve_on_failure <;> assumption
#print axioms OCS.Core.preserve_on_failure

example (old : Publication) (next : Nat) :
    (publish old next true true).active = some next := by
  apply install_valid <;> assumption
#print axioms OCS.Core.install_valid

example (old : Publication) (updates : List (Nat × Bool × Bool))
    (rejected : ∀ u ∈ updates, (u.2.1 && u.2.2) = false) : replayUpdates old updates = old := by
  apply arbitrary_failed_updates <;> assumption
#print axioms OCS.Core.arbitrary_failed_updates

example (initial : Nat) (hops : List Nat) :
    throughHops initial hops ≤ initial := by
  apply deadlines_decrease <;> assumption
#print axioms OCS.Core.deadlines_decrease

example (s : Resources) (e : Event) : occupancy (advance s e) = occupancy s := by
  apply step_conserves <;> assumption
#print axioms OCS.Core.step_conserves

example (s : Resources) (trace : List Event) :
    occupancy (history s trace) = occupancy s := by
  apply capacity_invariant <;> assumption
#print axioms OCS.Core.capacity_invariant

example (limit : Nat) (trace : List Event) :
    (history ⟨limit, 0⟩ trace).serving ≤ limit := by
  apply busy_bound <;> assumption
#print axioms OCS.Core.busy_bound

example (busy : Nat) : advance ⟨0,busy⟩ .admit = ⟨0,busy⟩ := by
  apply zero_capacity_denies <;> assumption
#print axioms OCS.Core.zero_capacity_denies

example (free busy : Nat) : (advance ⟨free+1,busy⟩ .admit).serving = busy+1 := by
  apply capacity_progress <;> assumption
#print axioms OCS.Core.capacity_progress

example (p a r i : Bool) (q : Option Nat) (budget : Nat) :
    nativeAdmission p a r i .hard q budget = true ↔
      p = true ∧ a = true ∧ r = true ∧ i = true ∧ ∃ n, q = some n ∧ 0 < n ∧ n ≤ budget := by
  apply hard_requires_bound <;> assumption
#print axioms OCS.Core.hard_requires_bound

example : nativeAdmission true true true true .soft none 0 = true := by
  apply native_soft_witness <;> assumption
#print axioms OCS.Core.native_soft_witness

example : nativeAdmission true true true true .hard none 100 = false := by
  apply native_hard_refusal <;> assumption
#print axioms OCS.Core.native_hard_refusal

example : reobserve .unresolved none = .unresolved := by
  apply unknown_on_lost_evidence <;> assumption
#print axioms OCS.Core.unknown_on_lost_evidence

example {α β : Type} (a b c : VersionedContract α β)
    (ab : Refines a b) (bc : Refines b c) : Refines a c := by
  apply transitive_refinement <;> assumption
#print axioms OCS.Core.transitive_refinement

example : Realizable statusContract := by
  apply status_realizable <;> assumption
#print axioms OCS.Core.status_realizable

example : statusContract.inputs 0 ∧ statusContract.results 0 0 := by
  apply valid_status_witness <;> assumption
#print axioms OCS.Core.valid_status_witness

example : ¬ statusContract.results 0 1 := by
  apply wrong_status_forbidden <;> assumption
#print axioms OCS.Core.wrong_status_forbidden

example {edge : Nat → Nat → Prop} (rank : Nat → Nat)
    (decreasing : ∀ a b, edge a b → rank b < rank a) {a b} (path : Path edge a b) :
    rank b < rank a := by
  apply rank_decreases_on_path <;> assumption
#print axioms OCS.Core.rank_decreases_on_path

example {edge : Nat → Nat → Prop} (rank : Nat → Nat)
    (decreasing : ∀ a b, edge a b → rank b < rank a) (a : Nat) : ¬ Path edge a a := by
  apply rank_excludes_cycle <;> assumption
#print axioms OCS.Core.rank_excludes_cycle

example {α : Type} (known extra : List α) :
    (forwardOptional known extra).drop known.length = extra := by
  apply forward_preserves_optional <;> assumption
#print axioms OCS.Core.forward_preserves_optional

example (grant : Bool) : actionable false grant = false := by
  apply no_evidence_no_action <;> assumption
#print axioms OCS.Core.no_evidence_no_action

example (record : TraceRecord) (a b : String) :
    publicRecord record a = publicRecord record b := by
  apply public_record_noninterference <;> assumption
#print axioms OCS.Core.public_record_noninterference

example (a b : Nat) : Identity.account a ≠ Identity.operation b := by
  apply identity_disjoint <;> assumption
#print axioms OCS.Core.identity_disjoint

example (e : Edge) (distinct : e.caller ≠ e.receiver) :
    routes e e.receiver e.caller e.resource = false := by
  apply reverse_is_unbound <;> assumption
#print axioms OCS.Core.reverse_is_unbound

example (e : Edge) : routes e e.caller e.receiver e.resource = true := by
  apply bound_route_exists <;> assumption
#print axioms OCS.Core.bound_route_exists

example (g : Grant) (inactive : g.effect = false) :
    byPermissionRequest g true = false := by
  apply no_grant_from_request <;> assumption
#print axioms OCS.Core.no_grant_from_request

example (state : Outcome) (elapsed : Nat) :
    afterDeadline state elapsed = state := by
  apply elapsed_does_not_rollback <;> assumption
#print axioms OCS.Core.elapsed_does_not_rollback

example (before now : Grant) (h : ¬ allowed now) :
    atEffect before now = false := by
  apply fresh_grant_required <;> assumption
#print axioms OCS.Core.fresh_grant_required

example : Refines extendedStatus statusContract := by
  apply extension_preserves_status <;> assumption
#print axioms OCS.Core.extension_preserves_status

example : Realizable extendedStatus := by
  apply extended_status_realizable <;> assumption
#print axioms OCS.Core.extended_status_realizable

end OCS.Core
