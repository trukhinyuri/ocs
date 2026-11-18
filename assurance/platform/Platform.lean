import Std
set_option autoImplicit false

namespace Platform

structure Product where
  tenant : Nat
  id : Nat
  version : Nat
  applied : Option Nat
  desired : List Nat
  physical : Option (List Nat)
  retired : Bool
deriving DecidableEq

inductive View where | denied | deleted | pending | degraded | ready
deriving DecidableEq

def observe (tenant : Nat) (p : Product) : View :=
  if tenant != p.tenant then .denied
  else if p.retired then .deleted
  else if p.applied != some p.version then .pending
  else if p.physical == some p.desired then .ready else .degraded

theorem readyMeansObserved (tenant : Nat) (p : Product) (h : observe tenant p = .ready) :
    tenant = p.tenant ∧ p.retired = false ∧ p.applied = some p.version ∧
    p.physical = some p.desired := by
  by_cases same : tenant = p.tenant <;> cases active : p.retired <;>
    by_cases revision : p.applied = some p.version <;>
    by_cases present : p.physical = some p.desired <;> simp_all [observe]

def request (p : Product) (content : List Nat) : Product :=
  {p with version := p.version + 1, applied := none, desired := content, retired := false}

def materialize (p : Product) : Product :=
  {p with applied := some p.version, physical := some p.desired}

theorem acceptanceIsPending (p : Product) (content : List Nat) :
    observe p.tenant (request p content) = .pending := by simp [observe, request]

theorem reconciledRequestIsReady (p : Product) (content : List Nat) :
    observe p.tenant (materialize (request p content)) = .ready := by
  simp [observe, materialize, request]

theorem wrongTenant (p : Product) (tenant : Nat) (h : tenant ≠ p.tenant) :
    observe tenant p = .denied := by simp [observe, h]

def crossRead (imported exported online sameScope : Bool) (v : View) : View :=
  if imported && exported && online && sameScope then v else .denied

theorem peerRequiresBoth (i e connected scopedOK : Bool)
    (h : crossRead i e connected scopedOK .ready = .ready) :
    i = true ∧ e = true ∧ connected = true ∧ scopedOK = true := by
  cases i <;> cases e <;> cases connected <;> cases scopedOK <;> simp_all [crossRead]

theorem revokedPreservesLocal (p : Product) (localOwner : Nat) (i c s : Bool) :
    (observe localOwner p, crossRead i false c s .ready) = (observe localOwner p, .denied) := by
  simp [crossRead]

inductive RemoteOutcome where | unknown | applied | absent
deriving DecidableEq

def reconcileRemote (oid : Nat) (old : RemoteOutcome) (newEvidence : Option RemoteOutcome) :=
  (oid, newEvidence.getD old)

theorem interruptedOutcome (oid : Nat) :
    reconcileRemote oid .unknown none = (oid,RemoteOutcome.unknown) := rfl

structure Fence where
  owner : Nat
  activeWriter : Nat
  epoch : Nat
  state : Product
  pending : List Nat
deriving DecidableEq

def mayWrite (f : Fence) (owner writer epoch : Nat) :=
  (owner == f.owner) && (writer == f.activeWriter) && (epoch == f.epoch)

def migrate (f : Fence) (selected : Nat) : Fence :=
  {f with activeWriter := selected, epoch := f.epoch + 1}

theorem soleWriter (f : Fence) (owner a b epoch : Nat)
    (ha : mayWrite f owner a epoch = true) (hb : mayWrite f owner b epoch = true) : a = b := by
  simp [mayWrite] at ha hb
  exact ha.1.2.trans hb.1.2.symm

theorem retiredEpochCannotWrite (f : Fence) (next : Nat) :
    mayWrite (migrate f next) f.owner f.activeWriter f.epoch = false := by simp [mayWrite, migrate]

theorem migrationPreserves (f : Fence) (next : Nat) :
    (migrate f next).owner = f.owner ∧ (migrate f next).state = f.state ∧
    (migrate f next).pending = f.pending := by simp [migrate]

def nativeAdmission (platformOK abiOK ownerOK isolationOK requestedHard : Bool) : Bool :=
  platformOK && abiOK && ownerOK && isolationOK && !requestedHard

theorem nativeRequiresBoundary (p a o i h : Bool) (ok : nativeAdmission p a o i h = true) :
    p = true ∧ a = true ∧ o = true ∧ i = true ∧ h = false := by simp_all [nativeAdmission,and_assoc]

theorem hardTimingRefused (p a o i : Bool) : nativeAdmission p a o i true = false := by simp [nativeAdmission]

def readHandle (owner handleOwner epoch handleEpoch version handleVersion : Nat) :=
  (owner == handleOwner) && (epoch == handleEpoch) && (version == handleVersion)

theorem retiredHandleRefused (o h e previous v w : Nat) (changed : previous ≠ e) :
    readHandle o h e previous v w = false := by simp [readHandle, Ne.symm changed]

inductive Work where | admit | release
structure Queue where
  active : Nat
  tenant : Nat
deriving DecidableEq

def step (q : Queue) (g t : Nat) : Work → Queue
  | .admit => if q.active < g ∧ q.tenant < t then ⟨q.active+1,q.tenant+1⟩ else q
  | .release => if 0 < q.tenant ∧ 0 < q.active then ⟨q.active-1,q.tenant-1⟩ else q

def execute (q : Queue) (g t : Nat) : List Work → Queue
  | [] => q
  | w :: tail => execute (step q g t w) g t tail

private theorem boundsOne (q : Queue) (g t : Nat) (w : Work)
    (a : q.active ≤ g) (b : q.tenant ≤ t) :
    (step q g t w).active ≤ g ∧ (step q g t w).tenant ≤ t := by
  cases w with
  | admit => by_cases h : q.active < g ∧ q.tenant < t <;> simp [step, h] <;> omega
  | release => by_cases h : 0 < q.tenant ∧ 0 < q.active <;> simp [step, h] <;> omega

theorem finiteCell (q : Queue) (g t : Nat) (trace : List Work) (a : q.active ≤ g) (b : q.tenant ≤ t) :
    (execute q g t trace).active ≤ g ∧ (execute q g t trace).tenant ≤ t := by
  induction trace generalizing q with
  | nil => exact ⟨a,b⟩
  | cons w tail ih =>
    obtain ⟨x,y⟩ := boundsOne q g t w a b
    exact ih (step q g t w) x y

theorem witness : nativeAdmission true true true true false = true ∧
    nativeAdmission true false true true false = false ∧ (step ⟨4,1⟩ 4 2 .admit).active = 4 := by decide

end Platform
