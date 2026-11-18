/- Protected finite Safe Push decision and its state-machine theorem.
   Identifiers and digests are encoded injectively as natural-number byte strings.
   Receipt facts originate at the separately administered receiver boundary. -/
import Std

set_option autoImplicit false
namespace SafePush

inductive Direction where | minimize | maximize
  deriving DecidableEq, Repr

structure Metric where
  direction : Direction
  condition : Nat
  value : Rat
  deriving DecidableEq, Repr

def atLeastAsGood (old next : Metric) : Prop :=
  old.direction = next.direction ∧ old.condition = next.condition ∧
    match old.direction with
    | .minimize => next.value ≤ old.value
    | .maximize => old.value ≤ next.value

def metricOK (old next : Metric) : Bool :=
  old.direction == next.direction && old.condition == next.condition &&
    match old.direction with
    | .minimize => decide (next.value ≤ old.value)
    | .maximize => decide (old.value ≤ next.value)

theorem metric_exact (old next : Metric) : metricOK old next = true ↔ atLeastAsGood old next := by
  cases old with | mk direction condition value =>
    cases direction <;> simp [metricOK, atLeastAsGood, and_assoc]

theorem metric_transitive (a b c : Metric) (ab : atLeastAsGood a b) (bc : atLeastAsGood b c) :
    atLeastAsGood a c := by
  rcases a with ⟨da, ka, va⟩
  rcases b with ⟨db, kb, vb⟩
  rcases c with ⟨dc, kc, vc⟩
  obtain ⟨deq, keq, first⟩ := ab
  obtain ⟨deq', keq', second⟩ := bc
  change da = db at deq; change db = dc at deq'
  change ka = kb at keq; change kb = kc at keq'
  subst db; subst dc; subst kb; subst kc
  cases da
  · exact ⟨rfl, rfl, Rat.le_trans second first⟩
  · exact ⟨rfl, rfl, Rat.le_trans first second⟩

/-- The finite input uses a balanced tree to keep an actual concrete proof shallow. -/
inductive Table (α : Type) where
  | empty
  | node (left : Table α) (key : Nat) (value : α) (right : Table α)
  deriving Repr

namespace Table

def all {α : Type} (p : α → Bool) : Table α → Bool
  | .empty => true
  | .node l _ v r => p v && l.all p && r.all p

def entries {α : Type} : Table α → List (Nat × α)
  | .empty => []
  | .node l k v r => l.entries ++ (k,v) :: r.entries

def ordered {α : Type} (low high : Option Nat) : Table α → Bool
  | .empty => true
  | .node left key _ right =>
    (low.all fun b => decide (b < key)) && (high.all fun b => decide (key < b)) &&
    left.ordered low (some key) && right.ordered (some key) high

theorem each {α : Type} (p : α → Bool) (t : Table α) (allPass : t.all p = true)
    (key : Nat) (v : α) (member : (key,v) ∈ t.entries) : p v = true := by
  induction t with
  | empty => simp [entries] at member
  | node l k x r il ir =>
    simp only [all, Bool.and_eq_true] at allPass
    simp only [entries, List.mem_append, List.mem_cons] at member
    rcases member with hl | same | hr
    · exact il allPass.1.2 hl
    · cases same; exact allPass.1.1
    · exact ir allPass.2 hr

theorem all_iff {α : Type} (p : α → Bool) (t : Table α) :
    t.all p = true ↔ ∀ k v, (k,v) ∈ t.entries → p v = true := by
  refine ⟨each p t, ?_⟩
  induction t with
  | empty => simp [all]
  | node l k v r il ir =>
    intro every
    have here := every k v (by simp [entries])
    have left := il fun key value h => every key value (by simp [entries, h])
    have right := ir fun key value h => every key value (by simp [entries, h])
    simp [all, here, left, right]

end Table

structure Change (α : Type) where
  before : Option α
  after : Option α
  deriving Repr

def retained {α : Type} (compare : α → α → Bool) (c : Change α) : Bool :=
  match c.before, c.after with
  | none, some _ => true
  | some a, some b => compare a b
  | _, _ => false

def retention {α : Type} (relation : α → α → Prop) (c : Change α) : Prop :=
  match c.before, c.after with
  | none, some _ => True
  | some a, some b => relation a b
  | _, _ => False

theorem retained_exact {α : Type} (compare : α → α → Bool) (relation : α → α → Prop)
    (equivalent : ∀ a b, compare a b = true ↔ relation a b) (rows : Table (Change α)) :
    rows.all (retained compare) = true ↔
      ∀ k change, (k,change) ∈ rows.entries → retention relation change := by
  have point (c : Change α) : retained compare c = true ↔ retention relation c := by
    rcases c with ⟨old,cur⟩
    cases old <;> cases cur <;> simp [retained, retention, equivalent]
  rw [Table.all_iff]
  exact ⟨fun all k c mem => (point c).mp (all k c mem),
         fun all k c mem => (point c).mpr (all k c mem)⟩

def view {α : Type} (side : Change α → Option α) (rows : Table (Change α)) : List (Nat × α) :=
  rows.entries.filterMap fun row => (side row.2).map fun value => (row.1,value)

theorem carried {α : Type} (compare : α → α → Bool) (rows : Table (Change α))
    (checked : rows.all (retained compare) = true) (k : Nat) (v : α)
    (member : (k,v) ∈ view Change.before rows) :
    ∃ w, (k,w) ∈ view Change.after rows ∧ compare v w = true := by
  obtain ⟨⟨key, c⟩, found, projected⟩ := List.mem_filterMap.mp member
  cases c with | mk old next =>
    cases old with
    | none => simp at projected
    | some a =>
      change (Option.some (key,a)) = some (k,v) at projected
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj projected)
      have passed := Table.each (retained compare) rows checked key ⟨some a,next⟩ found
      cases next with
      | none => simp [retained] at passed
      | some b =>
        exact ⟨b, List.mem_filterMap.mpr ⟨(key,⟨some a,some b⟩),found,rfl⟩, passed⟩

structure Facts where
  singleParent : Bool
  inventory : Bool
  qualification : Bool
  domainReview : Bool
  independentReview : Bool
  fresh : Bool
  noCounterexample : Bool
  policyContinuity : Bool
  priorEvidence : Bool
  deriving Repr

def factsOK (f : Facts) : Bool :=
  f.singleParent && f.inventory && f.qualification && f.domainReview && f.independentReview &&
    f.fresh && f.noCounterexample && f.policyContinuity && f.priorEvidence

def obligations (f : Facts) : Prop :=
  f.singleParent = true ∧ f.inventory = true ∧ f.qualification = true ∧ f.domainReview = true ∧
    f.independentReview = true ∧ f.fresh = true ∧ f.noCounterexample = true ∧
    f.policyContinuity = true ∧ f.priorEvidence = true

theorem facts_exact (f : Facts) : factsOK f = true ↔ obligations f := by
  simp [factsOK, obligations, and_assoc]

structure Packet where
  expectedParent : Nat
  observedParent : Nat
  candidate : Nat
  tree : Nat
  facts : Facts
  claims : Table (Change Nat)
  metrics : Table (Change Metric)
  deriving Repr

def gate (p : Packet) : Bool :=
  p.expectedParent == p.observedParent && p.candidate != p.expectedParent &&
    factsOK p.facts && p.claims.ordered none none && p.metrics.ordered none none &&
    p.claims.all (retained fun a b => a == b) && p.metrics.all (retained metricOK)

/-- A declarative, bidirectional decision for every well-formed finite packet. -/
theorem gate_exact (p : Packet) : gate p = true ↔
    p.expectedParent = p.observedParent ∧ p.candidate ≠ p.expectedParent ∧ obligations p.facts ∧
    p.claims.ordered none none = true ∧ p.metrics.ordered none none = true ∧
    (∀ k c, (k,c) ∈ p.claims.entries → retention Eq c) ∧
    (∀ k c, (k,c) ∈ p.metrics.entries → retention atLeastAsGood c) := by
  have claims := retained_exact (fun (a b : Nat) => a == b) Eq (fun _ _ => beq_iff_eq) p.claims
  have metrics := retained_exact metricOK atLeastAsGood metric_exact p.metrics
  simp only [gate, Bool.and_eq_true, bne_iff_ne, beq_iff_eq, facts_exact, claims, metrics, and_assoc]

structure Ledger where
  claims : List (Nat × Nat)
  metrics : List (Nat × Metric)
  deriving DecidableEq

def previous (p : Packet) : Ledger := ⟨view Change.before p.claims, view Change.before p.metrics⟩
def proposed (p : Packet) : Ledger := ⟨view Change.after p.claims, view Change.after p.metrics⟩

def preserves (a b : Ledger) : Prop :=
  (∀ k digest, (k,digest) ∈ a.claims → (k,digest) ∈ b.claims) ∧
  (∀ k old, (k,old) ∈ a.metrics →
    ∃ next, (k,next) ∈ b.metrics ∧ atLeastAsGood old next)

theorem decision_sound (p : Packet) (accepted : gate p = true) :
    p.expectedParent = p.observedParent ∧ p.candidate ≠ p.expectedParent ∧
    obligations p.facts ∧ preserves (previous p) (proposed p) := by
  simp only [gate, Bool.and_eq_true, beq_iff_eq, bne_iff_ne] at accepted
  obtain ⟨⟨⟨⟨⟨⟨parent, different⟩, facts⟩, _⟩, _⟩, claims⟩, metrics⟩ := accepted
  refine ⟨parent, different, (facts_exact _).mp facts, ?_, ?_⟩
  · intro k d hk
    obtain ⟨w, present, equal⟩ := carried _ _ claims k d hk
    change (d == w) = true at equal
    obtain rfl := beq_iff_eq.mp equal
    exact present
  · intro k v hk
    obtain ⟨w, present, good⟩ := carried _ _ metrics k v hk
    exact ⟨w, present, (metric_exact _ _).mp good⟩

theorem preservation_transitive (a b c : Ledger) (ab : preserves a b) (bc : preserves b c) :
    preserves a c := by
  refine ⟨fun k d mem => bc.1 k d (ab.1 k d mem), ?_⟩
  intro k v mem
  obtain ⟨w, bw, first⟩ := ab.2 k v mem
  obtain ⟨z, cz, second⟩ := bc.2 k w bw
  exact ⟨z, cz, metric_transitive v w z first second⟩

theorem preservation_refl (s : Ledger) : preserves s s := by
  refine ⟨fun _ _ h => h, ?_⟩
  intro k v h
  refine ⟨v,h,rfl,rfl,?_⟩
  cases v.direction <;> exact Rat.le_refl

structure Receipt where
  parent : Nat
  candidate : Nat
  tree : Nat
  packet : Packet
structure State where
  tip : Nat
  tree : Nat
  ledger : Ledger
  committed : List Receipt
  revoked : List Nat

/-- External receiver facts are re-evaluated before this CAS. It succeeds only
    at the observed parent, with that parent's complete protected durable ledger. -/
def committedState (s : State) (p : Packet) : State :=
  ⟨p.candidate,p.tree,proposed p,⟨s.tip,p.candidate,p.tree,p⟩ :: s.committed,s.revoked⟩

def publish (s : State) (p : Packet) : Option State :=
  if gate p = true ∧ p.observedParent = s.tip ∧ previous p = s.ledger ∧
     s.tip ∉ s.revoked ∧ p.candidate ∉ s.revoked then
    some (committedState s p)
  else none

theorem exact_commit (s : State) (p : Packet) (next : State) (sent : publish s p = some next) :
    gate p = true ∧ p.expectedParent = s.tip ∧ next.tip = p.candidate ∧ next.tree = p.tree ∧
    next.committed = ⟨s.tip,p.candidate,p.tree,p⟩ :: s.committed ∧ preserves s.ledger next.ledger := by
  unfold publish at sent
  split at sent
  next h =>
    cases sent
    obtain ⟨ok, observed, prior, _, _⟩ := h
    obtain ⟨expected, _, _, kept⟩ := decision_sound p ok
    exact ⟨ok,expected.trans observed,rfl,rfl,rfl,prior ▸ kept⟩
  next => contradiction

theorem stale_competing_parent (s next : State) (a b : Packet) (first : publish s a = some next)
    (same : b.observedParent = a.observedParent) : publish next b = none := by
  have accepted := exact_commit s a next first
  have different := (decision_sound a accepted.1).2.1
  have head := accepted.2.2.1
  have old := (decision_sound a accepted.1).1
  simp [publish, same, head, old.symm, Ne.symm different]

theorem revoke_blocks (s : State) (p : Packet)
    (blocked : s.tip ∈ s.revoked ∨ p.candidate ∈ s.revoked) : publish s p = none := by
  rcases blocked with h | h <;> simp [publish, h]

/-- Restart trusts the durable ref read-back and the enrolled last committed
    record. A prepared receipt becomes committed only for the exact observed ref.
    Later revocation affects present eligibility, never the historical record. -/
def sealedTransition (s : State) (p : Packet) : Option State :=
  if gate p = true ∧ p.observedParent = s.tip ∧ previous p = s.ledger then
    some (committedState s p)
  else none

theorem seal_at_publication (s next : State) (p : Packet) (sent : publish s p = some next) :
    sealedTransition s p = some next := by
  unfold publish at sent
  split at sent
  next h =>
    obtain ⟨ok, observed, ledger, _, _⟩ := h
    simpa [sealedTransition,ok,observed,ledger] using sent
  next => contradiction

def recover (s : State) (durableRef : Nat) (pending : Option Packet) : Option State :=
  if durableRef = s.tip then some s else
  match pending with
  | none => none
  | some p => if durableRef = p.candidate then sealedTransition s p else none

theorem unpublished_restart (s : State) (p : Option Packet) : recover s s.tip p = some s := by simp [recover]

theorem published_restart (s next : State) (p : Packet) (sent : publish s p = some next) :
    recover s p.candidate (some p) = some next := by
  have result := exact_commit s p next sent
  have changed : p.candidate ≠ s.tip := by
    rw [← result.2.1]
    exact (decision_sound p result.1).2.1
  simp [recover, changed, seal_at_publication s next p sent]

theorem restart_idempotent (s next : State) (p : Packet) (sent : publish s p = some next) :
    recover next p.candidate (some p) = some next := by simp [recover, (exact_commit s p next sent).2.2.1]

theorem foreign_ref_refuses (s : State) (p : Packet) (seen : Nat)
    (different : seen ≠ s.tip) (unbound : seen ≠ p.candidate) : recover s seen (some p) = none := by
  simp [recover, different, unbound]

theorem recovered_with_later_holds (s next : State) (p : Packet) (holds : List Nat)
    (sent : publish s p = some next) :
    recover {s with revoked := holds ++ s.revoked} p.candidate (some p) =
      some {next with revoked := holds ++ next.revoked} := by
  unfold publish at sent
  split at sent
  next h =>
    cases sent
    obtain ⟨ok, observed, old, _, _⟩ := h
    have different : p.candidate ≠ s.tip := by
      rw [← observed, ← (decision_sound p ok).1]
      exact (decision_sound p ok).2.1
    simp [recover, sealedTransition, committedState, different, ok, observed, old]
  next => contradiction

inductive Event where | attempt (p : Packet) | revoke (commit : Nat)

def advance (s : State) : Event → State
  | .attempt p => (publish s p).getD s
  | .revoke commit => {s with revoked := commit :: s.revoked}

def eligible (s : State) : Prop := s.tip ∉ s.revoked

theorem quarantine_current (s : State) :
    ¬ eligible (advance s (.revoke s.tip)) ∧ (advance s (.revoke s.tip)).committed = s.committed := by
  simp [eligible, advance]

def history (s : State) : List Event → State
  | [] => s
  | event :: rest => history (advance s event) rest

theorem step_preserves (s : State) (e : Event) : preserves s.ledger (advance s e).ledger := by
  cases e with
  | revoke => exact preservation_refl _
  | attempt p =>
    cases h : publish s p with
    | none => simpa [advance,h] using preservation_refl s.ledger
    | some next => simpa [advance,h] using (exact_commit s p next h).2.2.2.2.2

theorem arbitrary_history (s : State) (events : List Event) :
    preserves s.ledger (history s events).ledger := by
  induction events generalizing s with
  | nil => exact preservation_refl _
  | cons e rest ih => exact preservation_transitive _ _ _ (step_preserves s e) (ih (advance s e))

def verifiedReceipt (r : Receipt) : Prop :=
  gate r.packet = true ∧ r.parent = r.packet.expectedParent ∧ r.candidate = r.packet.candidate ∧
  r.tree = r.packet.tree ∧ preserves (previous r.packet) (proposed r.packet)

theorem step_journal (s : State) (e : Event)
    (prior : ∀ r ∈ s.committed, verifiedReceipt r) :
    ∀ r ∈ (advance s e).committed, verifiedReceipt r := by
  cases e with
  | revoke => exact prior
  | attempt p =>
    cases sent : publish s p with
    | none => simpa [advance,sent] using prior
    | some next =>
      obtain ⟨accepted, parent, _, _, journal, _⟩ := exact_commit s p next sent
      intro r member
      simp only [advance, sent, Option.getD_some] at member
      rw [journal] at member
      cases List.mem_cons.mp member with
      | inl first =>
        rw [first]
        exact ⟨accepted,parent.symm,rfl,rfl,(decision_sound p accepted).2.2.2⟩
      | inr earlier => exact prior r earlier

theorem history_journal (s : State) (events : List Event)
    (prior : ∀ r ∈ s.committed, verifiedReceipt r) :
    ∀ r ∈ (history s events).committed, verifiedReceipt r := by
  induction events generalizing s with
  | nil => exact prior
  | cons e _ ih => exact ih (advance s e) (step_journal s e prior)

def complete : Facts := ⟨true,true,true,true,true,true,true,true,true⟩
def sample : Packet := ⟨1,1,2,3,complete,
  .node .empty 7 ⟨some 9,some 9⟩ .empty,
  .node .empty 8 ⟨some ⟨.minimize,11,2⟩,some ⟨.minimize,11,1⟩⟩ .empty⟩

theorem nonvacuity :
    gate sample = true ∧ gate {sample with observedParent := 4} = false := by decide

end SafePush
