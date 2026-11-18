import Std

namespace OCS.Provider

structure Identity where
  issuer : Nat
  subject : Nat
  product : Nat
  account : Nat
  organization : Nat
  route : Nat
  method : Nat
  plan : Nat
  pool : Nat
deriving DecidableEq, Repr

structure Intent where
  identity : Identity
  packageVersion : Nat
  manifestPin : Nat
  operation : Nat
  contractVersion : Nat
  target : Nat
  input : Nat
  preconditions : Nat
deriving DecidableEq, Repr

inductive Quantity where
  | known (value : Nat) | percent (value : Nat) | unlimited | unknown | stale (value : Nat) | unsupported
deriving DecidableEq, Repr

inductive Price where
  | published (minor : Nat) | confirmed (minor : Nat) | contractual | unpublished | unknown
deriving DecidableEq, Repr

inductive Disposition where
  | pending | applied | uncertain | rejected
deriving DecidableEq, Repr

structure Effect where
  result : Disposition
  dispatches : Nat
deriving DecidableEq, Repr

inductive Event where
  | prepare | readback | commit (approved eligible unknownDelivery : Bool)
  | reconcile (evidenceOfApplication : Bool)
deriving DecidableEq, Repr

def fresh : Effect := ⟨.pending, 0⟩

def step (s : Effect) : Event → Effect
  | .prepare | .readback => s
  | .commit approved eligible uncertain =>
    if s.result = .pending ∧ approved = true ∧ eligible = true then
      ⟨if uncertain then .uncertain else .applied, s.dispatches + 1⟩
    else s
  | .reconcile confirmed =>
    if s.result = .uncertain ∧ confirmed = true then ⟨.applied, s.dispatches⟩ else s

def trace (s : Effect) : List Event → Effect
  | [] => s
  | op :: tail => trace (step s op) tail

def invariant (s : Effect) : Prop :=
  s.dispatches ≤ 1 ∧ (s.result = .pending → s.dispatches = 0)

def publish (prior candidate : Nat) (same complete last : Bool) :=
  if same ∧ complete ∧ last then candidate else prior

structure Totals where
  entries : Nat → Option Nat
  amount : Nat

def record (s : Totals) (key qty : Nat) : Totals :=
  match s.entries key with
  | some _ => s
  | none => ⟨fun k => if k = key then some qty else s.entries k, s.amount + qty⟩

def meterResult (s : Totals) (key qty : Nat) : Nat :=
  match s.entries key with
  | none => 0
  | some original => if original = qty then 1 else 2

def poolObserve (s : Totals) (key qty : Nat) (compatible independent known : Bool) : Totals :=
  if compatible ∧ independent ∧ known then record s key qty else s

def committedPrice : Price → Option Nat
  | .published amount | .confirmed amount => some amount
  | _ => none

def countable : Quantity → Option Nat
  | .known amount => some amount
  | _ => none

def authentic (subject issuer origin : Nat) (ticket : Nat × Nat × Nat) (expired used : Bool) : Bool :=
  ticket == (subject,issuer,origin) && !expired && !used

def eligible (active signed entitled supported route options : Bool) : Bool :=
  active && signed && entitled && supported && route && options

def propose (prior : Option Intent) (intent : Intent) : Nat :=
  match prior with
  | none => 0
  | some saved => if saved = intent then 1 else 2

def directAllowed (external monetary destructive irreversible : Bool) : Bool :=
  !(external || monetary || destructive || irreversible)

def usageClass (attributed probe fallback : Bool) : Nat :=
  if !attributed then 3 else if probe then 1 else if fallback then 2 else 0

-- These independently stated types are replayed against implementation proofs.
def Once := ∀ events : List Event, (trace fresh events).dispatches ≤ 1
def Inert := ∀ s : Effect, step s .prepare = s
def NoRetry := ∀ (s : Effect) (a b c : Bool), s.result = .uncertain → step s (.commit a b c) = s
def NoAuthority := ∀ (s : Effect) (eligible unknown : Bool), step s (.commit false eligible unknown) = s
def NoEligibility := ∀ (s : Effect) (approved unknown : Bool), step s (.commit approved false unknown) = s
def GoodWitness := trace fresh [.prepare, .commit true true false, .readback] = ⟨.applied, 1⟩
def BadWitness := trace fresh [.prepare, .commit false true false, .readback] = fresh
def UnknownWitness := trace fresh [.commit true true true, .commit true true true, .readback] = ⟨.uncertain, 1⟩
def RetainPartial := ∀ (s n : Nat) (same last : Bool), publish s n same false last = s
def RetainScope := ∀ (s n : Nat) (complete last : Bool), publish s n false complete last = s
def DuplicateMeter := ∀ (s : Totals) (k q : Nat), (record (record s k q) k q).amount = (record s k q).amount
def DuplicatePool := ∀ (s : Totals) (k q : Nat),
  (poolObserve (poolObserve s k q true true true) k q true true true).amount =
    (poolObserve s k q true true true).amount
def IndependentPools := ∀ (s : Totals) (a b x y : Nat),
  a ≠ b → s.entries a = none → s.entries b = none →
  (poolObserve (poolObserve s a x true true true) b y true true true).amount = s.amount + x + y
def ChangedMeter := ∀ (s : Totals) (k q r : Nat), s.entries k = some q → q ≠ r → meterResult s k r = 2
def EligibleExact := ∀ a b c d e f : Bool,
  eligible a b c d e f = true ↔ a=true ∧ b=true ∧ c=true ∧ d=true ∧ e=true ∧ f=true
end OCS.Provider
