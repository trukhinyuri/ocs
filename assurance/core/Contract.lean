import Std

namespace OCS.Core

/-- Independent authority dimensions. All fields describe the trusted host binding. -/
structure Grant where
  enabled : Bool
  issuer : Bool
  recipient : Bool
  scope : Bool
  effect : Bool
  revision : Bool
  deriving DecidableEq

def admits (g : Grant) : Bool :=
  g.enabled && g.issuer && g.recipient && g.scope && g.effect && g.revision

def allowed (g : Grant) : Prop :=
  g.enabled = true ∧ g.issuer = true ∧ g.recipient = true ∧ g.scope = true ∧
  g.effect = true ∧ g.revision = true

def conditional (rights : List Bool) : Bool := rights.all id

def eligible (required : List Bool) (_optional : List Bool) := conditional required

def identityForDisplay (_label : String) (issuer revision : Nat) := (issuer, revision)

structure Publication where
  active : Option Nat
  deriving DecidableEq

def publish (old : Publication) (candidate : Nat) (verified admitted : Bool) : Publication :=
  if verified && admitted then ⟨some candidate⟩ else old

def replayUpdates (old : Publication) (updates : List (Nat × Bool × Bool)) :=
  updates.foldl (fun current u => publish current u.1 u.2.1 u.2.2) old

def bound (deadline localBudget : Nat) := min deadline localBudget

def throughHops (initial : Nat) (hops : List Nat) := hops.foldl bound initial

structure Resources where
  available : Nat
  serving : Nat
  deriving DecidableEq

inductive Event where | admit | release | reject
  deriving DecidableEq

def advance : Resources → Event → Resources
  | ⟨0, busy⟩, .admit => ⟨0, busy⟩
  | ⟨free+1, busy⟩, .admit => ⟨free, busy+1⟩
  | ⟨free, 0⟩, .release => ⟨free, 0⟩
  | ⟨free, busy+1⟩, .release => ⟨free+1, busy⟩
  | s, .reject => s

def occupancy (s : Resources) := s.available + s.serving
def history (initial : Resources) (events : List Event) := events.foldl advance initial

inductive Timing where | bestEffort | soft | hard
  deriving DecidableEq

def nativeAdmission (platform abi authority isolation : Bool) (timing : Timing)
    (qualifiedWorstCase : Option Nat) (requestedLimit : Nat) : Bool :=
  platform && abi && authority && isolation &&
  match timing with
  | .hard => match qualifiedWorstCase with
    | none => false
    | some n => decide (0 < n ∧ n ≤ requestedLimit)
  | _ => true

inductive Outcome where | unresolved | refused | applied
  deriving DecidableEq

def reobserve (previous : Outcome) (authoritative : Option Outcome) :=
  authoritative.getD previous

structure VersionedContract (α β : Type) where
  inputs : α → Prop
  results : α → β → Prop

/-- Includes acceptance of old inputs and the allowed outputs on them. Progress
    is a distinct condition: a smaller set of outputs alone admits silent failure. -/
def Refines {α β : Type} (new old : VersionedContract α β) :=
  (∀ x, old.inputs x → new.inputs x) ∧
  (∀ x y, old.inputs x → new.results x y → old.results x y)

def Realizable {α β : Type} (c : VersionedContract α β) :=
  ∃ strategy : α → β, ∀ x, c.inputs x → c.results x (strategy x)

def statusContract : VersionedContract Nat Nat :=
  ⟨fun resource => resource = 0, fun resource reply => resource = 0 ∧ reply = resource⟩

inductive Path (edge : Nat → Nat → Prop) : Nat → Nat → Prop where
  | single {a b} : edge a b → Path edge a b
  | next {a b c} : Path edge a b → edge b c → Path edge a c

def forwardOptional {α : Type} (known extra : List α) := known ++ extra

def actionable (hasEvidence hasGrant : Bool) := hasEvidence && hasGrant

structure TraceRecord where
  parent : Nat
  request : Nat
  revision : Nat
  admitted : Bool
  millis : Nat
  deriving DecidableEq

def publicRecord (record : TraceRecord) (_secret : String) := record

inductive Identity where
  | principal : Nat → Identity
  | account : Nat → Identity
  | operation : Nat → Identity
  | resource : Nat → Identity
  deriving DecidableEq

structure Edge where
  caller : Identity
  receiver : Identity
  resource : Identity
  deriving DecidableEq

def routes (e : Edge) (src dst rid : Identity) : Bool :=
  decide (src = e.caller ∧ dst = e.receiver ∧ rid = e.resource)

def afterDeadline (before : Outcome) (_elapsed : Nat) : Outcome := reobserve before none
def byPermissionRequest (g : Grant) (_requestsWrite : Bool) := admits g

def extendedStatus : VersionedContract Nat Nat :=
  ⟨fun resource => resource ≤ 1, fun resource reply => resource ≤ 1 ∧ reply = resource⟩

def atEffect (_prior now : Grant) := admits now

/-- A trusted binding compares separately authenticated publisher evidence
    with the selected deployment/manifest. The display label is never a key. -/
structure PackageBinding where
  issuer : String
  domain : String
  packageId : String
  revision : String
  digest : String
  deriving DecidableEq

def bindAuthenticated (trusted observed : PackageBinding) (authenticated : Bool) :=
  authenticated && decide (trusted = observed)

inductive ObjectNamespace where | account | resource | conversation | operation | display
  deriving DecidableEq

structure ScopedIdentifier where
  kind : ObjectNamespace
  token : String
  deriving DecidableEq

structure EffectRecord where
  owner : Nat
  operationId : Nat
  intentDigest : Nat
  outcome : Outcome
  deriving DecidableEq

/-- A deadline can trigger observation by the owning authority. Only a receipt
    for this exact intent may establish a new outcome. -/
def reconcileAtDeadline (record : EffectRecord) (evidence : Option EffectRecord) : EffectRecord :=
  match evidence with
  | none => record
  | some later =>
    if (later.owner, later.operationId, later.intentDigest) =
       (record.owner, record.operationId, record.intentDigest)
    then {record with outcome := later.outcome} else record

/-- A concrete causal responder returns a permitted terminal reply for every
    admitted input. Option.none models silently refusing to make progress. -/
def Serves {α β : Type} (respond : α → Option β) (contract : VersionedContract α β) : Prop :=
  ∀ x, contract.inputs x → ∃ y, respond x = some y ∧ contract.results x y

def ProductiveRefinement {α β : Type} (new old : VersionedContract α β)
    (respond : α → Option β) : Prop := Refines new old ∧ Serves respond new

def runCalls {α β : Type} (respond : α → Option β) : List α → Option (List (α × β))
  | [] => some []
  | x :: tail =>
    match respond x, runCalls respond tail with
    | some y, some rest => some ((x,y) :: rest)
    | _, _ => none

def statusServer (greatest : Nat) (resource : Nat) : Option Nat :=
  if resource ≤ greatest then some resource else none

structure ScopedImport where
  operation : String
  version : String
  scope : String
  deriving DecidableEq

/-- The fixed assembly supplies a scope-indexed availability observation. -/
def callableWithImports (required : List Bool) (uses : List ScopedImport)
    (available : ScopedImport → Bool) := conditional required && uses.all available

structure EssentialMeaning where
  identity : String
  revision : String
  effect : String
  modality : String
  precision : String
  authority : String
  deriving DecidableEq

def forwardLossless {α : Type} (required : List String) (supports : String → Bool)
    (source destination : EssentialMeaning) (payload : α) : Option (EssentialMeaning × α) :=
  if required.all supports && decide (source = destination) then some (source,payload) else none

end OCS.Core
