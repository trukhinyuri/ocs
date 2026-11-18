import Std

set_option autoImplicit false

namespace Interaction

def admit (inspected admitted bound active ownerOK : Bool) (current seen : Nat) : Bool :=
  inspected && admitted && bound && active && ownerOK && (current == seen)

theorem revokedNoDispatch (i a b o : Bool) (current seen : Nat) :
    admit i a b false o current seen = false := by simp [admit]

theorem staleNoDispatch (i a b active o : Bool) (current seen : Nat) (h : current ≠ seen) :
    admit i a b active o current seen = false := by simp [admit, h]

theorem dispatchRequirements (i a b active o : Bool) (cur seen : Nat) :
    admit i a b active o cur seen = true ↔
    i = true ∧ a = true ∧ b = true ∧ active = true ∧ o = true ∧ cur = seen := by
  simp [admit, and_assoc]

def grant (parent exported imported scopedOK : Bool) := parent && exported && imported && scopedOK

def delegate (parent : Bool) : List Bool → Bool
  | [] => parent
  | edge :: tail => delegate (parent && edge) tail

theorem delegationNonAmplifying (parent : Bool) (edges : List Bool) :
    delegate parent edges = true ↔ parent = true ∧ ∀ e ∈ edges, e = true := by
  induction edges generalizing parent with
  | nil => simp [delegate]
  | cons edge tail ih => simp [delegate, ih, and_assoc]

def reserve (budget share : Nat) : Nat := if share ≤ budget then budget - share else budget

theorem reserveConserved (budget share : Nat) (h : share ≤ budget) :
    reserve budget share + share = budget := by simp [reserve, h]

def route (fuel : Nat) (edges : List Nat) := edges.take fuel

theorem cycleFuelTerminates (fuel : Nat) (edges : List Nat) :
    (route fuel edges).length ≤ fuel := List.length_take_le fuel edges

structure Stream where
  credit : Nat
  sent : Nat
  granted : Nat
  remaining : Nat
  finals : Nat
deriving DecidableEq, Repr

inductive Action where
  | give (amount : Nat)
  | send
  | finish
deriving DecidableEq, Repr

def tick (s : Stream) (action : Action) (owned : Bool) (cap : Nat) : Stream :=
  if owned && (s.finals == 0) then
    match action with
    | .give amount => if 0 < amount ∧ s.credit + amount ≤ cap then
        {s with credit := s.credit + amount, granted := s.granted + amount} else s
    | .send => if 0 < s.credit ∧ 0 < s.remaining then
        {s with credit := s.credit - 1, sent := s.sent + 1, remaining := s.remaining - 1} else s
    | .finish => {s with finals := 1}
  else s

abbrev Command := Action × Bool × Nat

def runStream (s : Stream) : List Command → Stream
  | [] => s
  | (a, o, c) :: tail => runStream (tick s a o c) tail

private theorem oneConserved (s : Stream) (a : Action) (o : Bool) (c : Nat)
    (h : s.credit + s.sent = s.granted) :
    (tick s a o c).credit + (tick s a o c).sent = (tick s a o c).granted := by
  by_cases gate : (o && (s.finals == 0)) = true
  · cases a with
    | give n => by_cases ok : 0 < n ∧ s.credit + n ≤ c <;> simp [tick, gate, ok] <;> omega
    | send => by_cases ok : 0 < s.credit ∧ 0 < s.remaining <;> simp [tick, gate, ok] <;> omega
    | finish => simpa [tick, gate] using h
  · simpa [tick, gate] using h

theorem streamConserved (s : Stream) (trace : List Command) (h : s.credit + s.sent = s.granted) :
    (runStream s trace).credit + (runStream s trace).sent = (runStream s trace).granted := by
  induction trace generalizing s with
  | nil => exact h
  | cons command tail ih =>
    rcases command with ⟨a, o, c⟩
    exact ih _ (oneConserved s a o c h)

private theorem oneFinal (s : Stream) (a : Action) (o : Bool) (c : Nat) (h : s.finals ≤ 1) :
    (tick s a o c).finals ≤ 1 := by
  by_cases gate : (o && (s.finals == 0)) = true
  · cases a with
    | give n => by_cases ok : 0 < n ∧ s.credit + n ≤ c <;> simpa [tick, gate, ok] using h
    | send => by_cases ok : 0 < s.credit ∧ 0 < s.remaining <;> simpa [tick, gate, ok] using h
    | finish => simp [tick, gate]
  · simpa [tick, gate] using h

theorem terminalAtMostOnce (s : Stream) (trace : List Command) (h : s.finals ≤ 1) :
    (runStream s trace).finals ≤ 1 := by
  induction trace generalizing s with
  | nil => exact h
  | cons cmd tail ih =>
    rcases cmd with ⟨a, o, c⟩
    exact ih _ (oneFinal s a o c h)

theorem closedIgnoresAll (s : Stream) (h : s.finals ≠ 0) (trace : List Command) :
    runStream s trace = s := by
  induction trace with
  | nil => rfl
  | cons cmd tail ih => rcases cmd with ⟨a,o,c⟩; simpa [runStream, tick, h] using ih

def drain (s : Stream) : Nat → Stream
  | 0 => tick s .finish true 0
  | n + 1 => drain (tick s .send true 0) n

theorem streamProgress (n : Nat) (s : Stream) (open_ : s.finals = 0)
    (enough : n ≤ s.credit) (work : s.remaining = n) :
    (drain s n).remaining = 0 ∧ (drain s n).finals = 1 ∧ (drain s n).sent = s.sent + n := by
  induction n generalizing s with
  | zero => simp [drain, tick, open_, work]
  | succ n ih =>
    have positive : 0 < s.credit := by omega
    let next := tick s .send true 0
    have equal : next = {s with credit := s.credit - 1, sent := s.sent + 1, remaining := n} := by
      simp [next, tick, open_, work, positive]
    have ho : next.finals = 0 := by simp [equal, open_]
    have hc : n ≤ next.credit := by simp [equal]; omega
    have hw : next.remaining = n := by simp [equal]
    obtain ⟨hr, hf, hs⟩ := ih next ho hc hw
    change (drain next n).remaining = 0 ∧ (drain next n).finals = 1 ∧ (drain next n).sent = s.sent + (n+1)
    exact ⟨hr, hf, by rw [hs, equal]; simp; omega⟩

theorem streamWitness : (drain ⟨2, 0, 2, 2, 0⟩ 2).sent = 2 := by decide
theorem creditRefusal : (tick ⟨0, 0, 0, 2, 0⟩ .send true 4).sent = 0 := by decide

def ack (old asked high : Nat) := if old ≤ asked ∧ asked ≤ high then asked else old
theorem ackMonotone (old asked high : Nat) : old ≤ ack old asked high := by
  unfold ack; split <;> omega

theorem ackWithin (old asked high : Nat) (h : old ≤ high) : ack old asked high ≤ high := by
  unfold ack; split <;> omega

inductive Phase where | waiting | done | cancelled
deriving DecidableEq, Repr
structure Job where
  state : Phase
  revision : Nat
  effectApplied : Bool
deriving DecidableEq, Repr

def canContinue (waiting owner : Bool) (revision expected : Nat) :=
  waiting && owner && (revision == expected)

def continueJob (j : Job) (owner : Bool) (expected : Nat) :=
  if canContinue (j.state == .waiting) owner j.revision expected then
    {j with state := .done, revision := j.revision + 1} else j

def cancelJob (j : Job) (owner : Bool) :=
  if owner && (j.state == .waiting) then {j with state := .cancelled, revision := j.revision + 1}
  else j

inductive JobAction where | resume (owner : Bool) (revision : Nat) | cancel (owner : Bool)
def jobs (j : Job) : List JobAction → Job
  | [] => j
  | .resume o r :: tail => jobs (continueJob j o r) tail
  | .cancel o :: tail => jobs (cancelJob j o) tail

theorem jobTerminalStable (j : Job) (h : j.state ≠ .waiting) (trace : List JobAction) :
    jobs j trace = j := by
  induction trace with
  | nil => rfl
  | cons act tail ih => cases act <;> simpa [jobs, continueJob, canContinue, cancelJob, h] using ih

theorem jobCasExclusive (j : Job) (owner : Bool) (expected : Nat)
    (accepted : canContinue (j.state == .waiting) owner j.revision expected = true) :
    canContinue ((continueJob j owner expected).state == .waiting) owner
      (continueJob j owner expected).revision expected = false := by
  simp only [continueJob, accepted, ite_true]; simp [canContinue]

theorem cancellationPreservesEffect (j : Job) (o : Bool) :
    (cancelJob j o).effectApplied = j.effectApplied := by unfold cancelJob; split <;> rfl

def pageSize (len offset budget : Nat) := min (len - offset) budget
theorem pageProgress (len off budget : Nat) (inside : off < len) (positive : 0 < budget) :
    0 < pageSize len off budget ∧ off + pageSize len off budget ≤ len ∧
    pageSize len off budget ≤ budget := by unfold pageSize; omega

theorem rangeReconstructs {α : Type} (xs : List α) (off n : Nat) :
    xs.take off ++ ((xs.drop off).take n ++ (xs.drop off).drop n) = xs := by rw [List.take_append_drop, List.take_append_drop]

inductive Delivery where | new | same | conflict | gap
deriving DecidableEq
def receive (seen same : Bool) (last seq : Nat) :=
  if seen then (if same then Delivery.same else .conflict)
  else if seq == last + 1 then .new else .gap
theorem duplicateSame (last seq : Nat) : receive true true last seq = .same := by rfl
theorem duplicateConflict (last seq : Nat) : receive true false last seq = .conflict := by rfl
theorem ordinalGap (last seq : Nat) (h : seq ≠ last + 1) : receive false true last seq = .gap := by
  simp [receive, h]

def observe {α : Type} (x : α) (_ : Nat) := x
theorem observationInert {α : Type} (x : α) (event : Nat) : observe x event = x := rfl

theorem dialogWitness : delegate true [true, true] = true ∧ delegate false [true] = false := by decide


structure Binding where
  tenant : Nat
  recipient : Nat
  resource : Nat
  epoch : Nat
  writeGrant : Bool
deriving DecidableEq

def scopedGrant (binding : Binding) (tenant recipient resource epoch : Nat)
    (fresh needsWrite downstreamImport downstreamExport : Bool) :=
  fresh && (binding.tenant == tenant) && (binding.recipient == recipient) &&
  (binding.resource == resource) && (binding.epoch == epoch) &&
  grant ((!needsWrite) || binding.writeGrant) downstreamExport downstreamImport true

theorem scopedDispatch (b : Binding) (t r o epoch : Nat) (fresh write imp exp : Bool)
    (accepted : scopedGrant b t r o epoch fresh write imp exp = true) :
    b.tenant = t ∧ b.recipient = r ∧ b.resource = o ∧ b.epoch = epoch ∧ fresh = true ∧
    imp = true ∧ exp = true ∧ (write = true → b.writeGrant = true) := by
  cases fresh <;> cases write <;> simp_all [scopedGrant, grant, and_assoc]

theorem partitionDenies (b : Binding) (t r o e : Nat) (write imp exp : Bool) :
    scopedGrant b t r o e false write imp exp = false := rfl

theorem forgedLabelInert (available readBinding needsWrite : Bool) (oldLabel newLabel : Nat) :
    (fun (_ : Nat) => grant available readBinding true (!needsWrite)) oldLabel =
    (fun (_ : Nat) => grant available readBinding true (!needsWrite)) newLabel := rfl

structure Message where
  id : Nat
  context : Nat
  issuer : Nat
  task : Option Nat
  parts : List Nat
deriving DecidableEq

structure Reply where
  inReplyTo : Nat
  context : Nat
  author : Nat
  originalIssuer : Nat
  task : Option Nat
  parts : List Nat
deriving DecidableEq

def reply (m : Message) (authority : Nat) (ordered : List Nat) : Reply :=
  ⟨m.id, m.context, authority, m.issuer, m.task, ordered⟩

theorem messageCorrelation (m : Message) (a : Nat) (p : List Nat) :
    (reply m a p).inReplyTo = m.id ∧ (reply m a p).context = m.context ∧
    (reply m a p).author = a ∧ (reply m a p).originalIssuer = m.issuer ∧
    (reply m a p).task = m.task ∧ (reply m a p).parts = p := by simp [reply]

inductive EffectState where | unconfirmed | completed (buffer : List Nat)
deriving DecidableEq

def readReceipt (s : EffectState) (ownerGranted : Bool) : Option (List Nat) × EffectState :=
  if ownerGranted then match s with
    | .unconfirmed => (none,s)
    | .completed buffer => (some buffer,s)
  else (none,s)

theorem readEffectsInert (s : EffectState) (o : Bool) : (readReceipt s o).2 = s := by
  cases s <;> cases o <;> rfl

theorem unconfirmedNeverReissued (o : Bool) :
    readReceipt .unconfirmed o = (none, .unconfirmed) := by cases o <;> rfl

def compensate (original proposal : Nat) (own approved : Bool) :=
  own && approved && !(original == proposal)

theorem newCompensation (original proposal : Nat) (own ok : Bool)
    (takesEffect : compensate original proposal own ok = true) :
    own = true ∧ ok = true ∧ original ≠ proposal := by
  simp [compensate, and_assoc] at takesEffect
  exact takesEffect

def nextHop (retryOwner : Nat) (budget : Nat) (consume : Nat) := (retryOwner,reserve budget consume)
theorem retryOwnerPreserved (owner fuel cost : Nat) :
    (nextHop owner fuel cost).1 = owner ∧ (nextHop owner fuel cost).2 ≤ fuel := by
  simp [nextHop, reserve]; split <;> omega

def availableRead (b : Binding) (tenant recipient resource epoch : Nat) (result : Nat) :
    Option Nat := if scopedGrant b tenant recipient resource epoch true false true true then
      some result else none

theorem replaceDependency (first second : Binding) (tenant recipient resource epoch result : Nat)
    (admitted1 : scopedGrant first tenant recipient resource epoch true false true true = true)
    (admitted2 : scopedGrant second tenant recipient resource epoch true false true true = true) :
    availableRead first tenant recipient resource epoch result =
    availableRead second tenant recipient resource epoch result := by simp [availableRead, admitted1, admitted2]


theorem sendOrdinal (s : Stream) (cap : Nat) (live : s.finals = 0)
    (credit : 0 < s.credit) (work : 0 < s.remaining) :
    (tick s .send true cap).sent = s.sent + 1 := by simp [tick, live, credit, work]

theorem finishExactlyOne (s : Stream) (cap : Nat) (h : s.finals = 0) :
    (tick s .finish true cap).finals = 1 ∧ (tick s .finish true cap).sent = s.sent := by simp [tick, h]

def possibleOpen (initial cap : Nat) := decide (0 < initial ∧ initial ≤ cap)
theorem openRequiresCredit (initial cap : Nat) :
    possibleOpen initial cap = true ↔ 0 < initial ∧ initial ≤ cap := by simp [possibleOpen]

def retained (old low high : Nat) := decide (low ≤ old ∧ old ≤ high)
theorem historyGap (old low high : Nat) (h : old < low) :
    retained old low high = false := by simp [retained]; omega

def verifyArtifact {α : Type} (data : List α) (hash : List α → Nat) (len digest : Nat) :=
  (data.length == len) && (hash data == digest)
theorem artifactIntegrity {α : Type} (data : List α) (hash : List α → Nat) (len digest : Nat)
    (accepted : verifyArtifact data hash len digest = true) : data.length = len ∧ hash data = digest := by
  simpa [verifyArtifact] using accepted

def walkFuel (next : Nat → Option Nat) (start : Nat) (seen : List Nat) : Nat → List Nat
  | 0 => []
  | n+1 => if start ∈ seen then [] else
    match next start with
    | none => []
    | some dest => start :: walkFuel next dest (start :: seen) n

theorem graphHopsBound (next : Nat → Option Nat) (start : Nat) (seen : List Nat) (fuel : Nat) :
    (walkFuel next start seen fuel).length ≤ fuel := by
  induction fuel generalizing start seen with
  | zero => simp [walkFuel]
  | succ n ih =>
    by_cases repeats : start ∈ seen
    · simp [walkFuel, repeats]
    · cases e : next start with
      | none => simp [walkFuel, repeats, e]
      | some dest => simpa [walkFuel, repeats, e] using ih dest (start :: seen)


structure ActionKey where
  operation : Nat
  version : Nat
deriving DecidableEq

def surfaceEligible (valid versionOK declared action grantOK : Bool) :=
  valid && versionOK && declared && action && grantOK

def admitsView (a : ActionKey) (valid : Bool) (manifest actions rights : List ActionKey) :=
  surfaceEligible valid true (decide (a ∈ manifest)) (decide (a ∈ actions)) (decide (a ∈ rights))

theorem viewScope (a : ActionKey) (ok : Bool) (manifest actions grants : List ActionKey) :
    admitsView a ok manifest actions grants = true ↔
    ok = true ∧ a ∈ manifest ∧ a ∈ actions ∧ a ∈ grants := by
  simp [admitsView,surfaceEligible,and_assoc]

def callbackAllowed (serial sameChan imported : Bool) := imported && !(serial && sameChan)

theorem callbackBoundary (serial sameChan allowed : Bool) :
    callbackAllowed serial sameChan allowed = true ↔ allowed = true ∧ (serial = true → sameChan = false) := by
  cases serial <;> cases sameChan <;> cases allowed <;> decide

theorem directionSeparatesID (rid : Nat) : (false,rid) ≠ (true,rid) := by simp

structure EventKey where
  scope : Nat
  source : Nat
  id : Nat
deriving DecidableEq

def put (prior : EventKey → Option Nat) (k : EventKey) (content : Nat) :=
  fun next => if next = k then some content else prior next

def delivery (prior : EventKey → Option Nat) (k : EventKey) (content : Nat) : Delivery :=
  match prior k with
  | none => .new
  | some earlier => if earlier = content then .same else .conflict

theorem keyedDelivery (prior : EventKey → Option Nat) (k : EventKey) (a b : Nat) :
    delivery (put prior k a) k b = (if a = b then .same else .conflict) := by simp [delivery,put]

theorem distinctPublication (prior : EventKey → Option Nat) (left right : EventKey) (a b : Nat)
    (different : right ≠ left) :
    delivery (put prior left a) right b = delivery prior right b := by simp [delivery,put,different]

theorem unauthorizedFinishInert (s : Stream) (cap : Nat) :
    tick s .finish false cap = s := by simp [tick]

def pumpOne (s : Stream) (cap : Nat) :=
  let ready := if s.credit = 0 then tick s (.give 1) true cap else s
  tick ready .send true cap

def pump (s : Stream) (cap : Nat) : Nat → Stream
  | 0 => tick s .finish true cap
  | n+1 => pump (pumpOne s cap) cap n

private theorem pumpStep (s : Stream) (cap : Nat) (live : s.finals = 0)
    (room : 1 ≤ cap) (work : 0 < s.remaining) :
    (pumpOne s cap).sent = s.sent + 1 ∧ (pumpOne s cap).finals = 0 ∧
    (pumpOne s cap).remaining = s.remaining - 1 := by
  by_cases empty : s.credit = 0
  · simp [pumpOne,tick,live,empty,room,work]
  · have positive : 0 < s.credit := by omega
    simp [pumpOne,tick,live,empty,positive,work]

theorem rollingCreditProgress (n cap : Nat) (s : Stream) (live : s.finals = 0)
    (room : 1 ≤ cap) (work : s.remaining = n) :
    (pump s cap n).remaining = 0 ∧ (pump s cap n).finals = 1 ∧ (pump s cap n).sent = s.sent+n := by
  induction n generalizing s with
  | zero => simp [pump,tick,live,work]
  | succ n ih =>
    have positive : 0 < s.remaining := by omega
    obtain ⟨sent, open_, left⟩ := pumpStep s cap live room positive
    have rem : (pumpOne s cap).remaining = n := by omega
    obtain ⟨zero, one, total⟩ := ih (pumpOne s cap) open_ rem
    change (pump (pumpOne s cap) cap n).remaining = 0 ∧ (pump (pumpOne s cap) cap n).finals = 1 ∧
        (pump (pumpOne s cap) cap n).sent = s.sent+(n+1)
    exact ⟨zero,one,by omega⟩

def pages {α : Type} (xs : List α) : List Nat → List α × List α
  | [] => ([],xs)
  | b :: rest => let later := pages (xs.drop b) rest
                 (xs.take b ++ later.1, later.2)

theorem pagesReassemble {α : Type} (xs : List α) (budgets : List Nat) :
    (pages xs budgets).1 ++ (pages xs budgets).2 = xs := by
  induction budgets generalizing xs with
  | nil => simp [pages]
  | cons b rest ih => simp only [pages,List.append_assoc]; rw [ih, List.take_append_drop]

theorem byteRankDrops (size off budget : Nat) (inside : off < size) (positive : 0 < budget) :
    size - (off + pageSize size off budget) < size - off := by
  obtain ⟨pos, bound, _⟩ := pageProgress size off budget inside positive
  omega


structure OwnedKey where
  tenant : Nat
  kind : Nat
  id : Nat
deriving DecidableEq

def ownerWrite (before : OwnedKey → Nat) (actor : Nat) (key : OwnedKey) (value : Nat) : OwnedKey → Nat :=
  fun q => if actor = key.tenant ∧ q = key then value else before q

def ownerWrites (before : OwnedKey → Nat) (actor : Nat) : List (OwnedKey × Nat) → OwnedKey → Nat
  | [] => before
  | (k,v)::rest => ownerWrites (ownerWrite before actor k v) actor rest

theorem tenantNoninterference (before : OwnedKey → Nat) (actor : Nat) (q : OwnedKey)
    (foreign : actor ≠ q.tenant) (updates : List (OwnedKey × Nat)) :
    ownerWrites before actor updates q = before q := by
  induction updates generalizing before with
  | nil => rfl
  | cons change tail ih =>
    rcases change with ⟨k,v⟩
    change ownerWrites (ownerWrite before actor k v) actor tail q = before q
    rw [ih]
    by_cases same : q = k
    · subst k; simp [ownerWrite,foreign]
    · simp [ownerWrite,same]


def reserveMany (budget : Nat) : List Nat → Option Nat
  | [] => some budget
  | s::rest => if s ≤ budget then reserveMany (reserve budget s) rest else none

theorem parallelConservation (shares : List Nat) (parent remaining : Nat)
    (ok : reserveMany parent shares = some remaining) :
    remaining + shares.sum = parent := by
  induction shares generalizing parent with
  | nil => simp [reserveMany] at ok; simp [ok]
  | cons first tail ih =>
    by_cases within : first ≤ parent
    · simp [reserveMany,within] at ok
      have child := ih (reserve parent first) ok
      have total := reserveConserved parent first within
      simp only [List.sum_cons]; omega
    · simp [reserveMany,within] at ok

theorem oversizedShareRefused (parent first : Nat) (tail : List Nat) (tooLarge : parent < first) :
    reserveMany parent (first::tail) = none := by
  have outside : ¬ first ≤ parent := by omega
  simp [reserveMany,outside]

end Interaction
