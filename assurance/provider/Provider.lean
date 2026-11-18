import Contract

namespace OCS.Provider

theorem eligible_exact : EligibleExact := by
  intro a b c d e f
  simp [eligible, Bool.and_eq_true, and_assoc]

theorem partial_preserves : RetainPartial := by simp [RetainPartial, publish]
theorem wrong_scope_preserves : RetainScope := by simp [RetainScope, publish]

theorem duplicate_meter_no_add : DuplicateMeter := by
  intro s k q
  cases h : s.entries k with
  | none => simp [record, h]
  | some v => simp [record, h]

theorem duplicate_pool_no_add : DuplicatePool := by
  intro s k q
  simpa [poolObserve] using duplicate_meter_no_add s k q

theorem independent_pools_add : IndependentPools := by
  intro s a b x y different ha hb
  have ba : b ≠ a := Ne.symm different
  simp [poolObserve, record, ha, hb, ba]

theorem incompatible_pool_preserves (s : Totals) (k q : Nat) (i n : Bool) :
    (poolObserve s k q false i n).amount = s.amount := by simp [poolObserve]

theorem changed_meter_conflicts : ChangedMeter := by
  intro s k q r h d
  simp [meterResult, h, d]

theorem prepare_inert : Inert := by intro s; rfl
theorem denial_preserves : NoAuthority := by simp [NoAuthority, step]
theorem stale_preserves : NoEligibility := by simp [NoEligibility, step]

theorem invariant_step {s : Effect} (inv : invariant s) (e : Event) : invariant (step s e) := by
  cases e with
  | prepare => exact inv
  | readback => exact inv
  | commit approved ok unknown =>
    simp only [step]
    split
    next h =>
      have n := inv.2 h.1
      cases unknown <;> simp [invariant, n]
    next => exact inv
  | reconcile evidence =>
    simp only [step]
    split
    next => simp [invariant, inv.1]
    next => exact inv

theorem invariant_trace (s : Effect) (h : invariant s) (ops : List Event) : invariant (trace s ops) := by
  induction ops generalizing s with
  | nil => exact h
  | cons head tail rest => exact rest (step s head) (invariant_step h head)

theorem once_over_trace : Once := by
  intro ops
  exact (invariant_trace fresh (by simp [fresh, invariant]) ops).1

theorem unknown_preserved : NoRetry := by
  intro s a b c hs
  simp [step, hs]

theorem commit_witness : GoodWitness := by rfl
theorem denial_witness : BadWitness := by rfl
theorem unknown_witness : UnknownWitness := by rfl

theorem readback_inert (s : Effect) : step s .readback = s := rfl
theorem terminal_readback (s : Effect) (a b c : Bool) (h : s.result = .applied) :
    step s (.commit a b c) = s := by simp [step, h]

theorem exact_scope (s i o : Nat) (ticket : Nat × Nat × Nat) (expired consumed : Bool) :
    authentic s i o ticket expired consumed = true ↔
      ticket = (s,i,o) ∧ expired = false ∧ consumed = false := by
  simp [authentic, Bool.and_eq_true, and_assoc]

theorem separate_identity (a b : Identity) :
    a = b ↔ a.issuer = b.issuer ∧ a.subject = b.subject ∧ a.product = b.product ∧
    a.account = b.account ∧ a.organization = b.organization ∧ a.route = b.route ∧
    a.method = b.method ∧ a.plan = b.plan ∧ a.pool = b.pool := by
  cases a; cases b; simp [Identity.mk.injEq]

theorem intent_changes_conflict (a b : Intent) (h : a ≠ b) : propose (some a) b = 2 := by
  simp [propose,h]

theorem identical_intent_replays (a : Intent) : propose (some a) a = 1 := by simp [propose]

theorem direct_consequence_denied (e m d i : Bool) :
    directAllowed e m d i = true ↔ e=false ∧ m=false ∧ d=false ∧ i=false := by
  cases e <;> cases m <;> cases d <;> cases i <;> decide

theorem zero_distinct :
  countable (.known 0) = some 0 ∧ countable .unknown = none ∧ countable .unlimited = none ∧
  countable (.percent 25) = none ∧ countable (.stale 0) = none ∧ countable .unsupported = none := by decide

theorem prices_distinct :
  committedPrice (.confirmed 0) = some 0 ∧ committedPrice .contractual = none ∧
  committedPrice .unknown = none ∧ committedPrice .unpublished = none := by decide

theorem usage_partition (a p f : Bool) :
  usageClass a p f = 0 ↔ a=true ∧ p=false ∧ f=false := by
  cases a <;> cases p <;> cases f <;> decide

def offerReset (count : Nat) (right term : Bool) : Bool :=
  decide (0 < count) && right && term

theorem reset_eligible (count : Nat) (right term : Bool) :
    offerReset count right term = true ↔ 0 < count ∧ right = true ∧ term = true := by
  simp [offerReset, Bool.and_eq_true, and_assoc]

def noticeVisible (_listings : List Nat) (notices : List (Nat × Nat)) (id : Nat) : Bool :=
  (notices.map Prod.fst).contains id

theorem derived_notice_absent (listings : List Nat) (notices : List (Nat × Nat)) (id : Nat)
    (absent : id ∉ notices.map Prod.fst) : noticeVisible listings notices id = false := by
  simp [noticeVisible, absent]

end OCS.Provider
