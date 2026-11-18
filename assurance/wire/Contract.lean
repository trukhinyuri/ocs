/- Sealed stdio session contract. Every Boolean is an independently variable
   observation of the parser/validator or of a comparison on decoded values.
   This module defines the target property independently of either executor. -/
namespace OCSWire

inductive Verdict
  | described | delivered | params | expired | incompatible | pin | method | input | denied
  deriving DecidableEq, Repr

abbrev Response := Bool × Verdict

structure Facts where
  shape : Bool
  metadata : Bool
  dateSyntax : Bool
  future : Bool
  trace : Bool
  protocols : Bool
  features : Bool
  featureNames : Bool
  coreOffered : Bool
  noRequired : Bool
  correlations : Bool
  pinSyntax : Bool
  nameSyntax : Bool
  versionSyntax : Bool
  protocolMatches : Bool
  pinMatches : Bool
  operationMatches : Bool
  versionMatches : Bool
  inputValid : Bool
  granted : Bool
  deriving Repr

def describe (traceFirst : Bool) (f : Facts) : Response :=
  if !f.shape || !f.metadata then (false, .params)
  else if traceFirst && !f.trace then (false, .params)
  else if !f.dateSyntax then (false, .params)
  else if !f.future then (false, .expired)
  else if !f.protocols || !f.features || !f.featureNames || !f.trace then (false, .params)
  else if !f.coreOffered || !f.noRequired then (false, .incompatible)
  else (true, .described)

def invoke (s : Bool) (f : Facts) : Response :=
  if !f.shape || !f.metadata then (s, .params)
  else if !f.dateSyntax then (s, .params)
  else if !f.future then (s, .expired)
  else if !f.correlations || !f.pinSyntax || !f.nameSyntax || !f.versionSyntax then (s, .params)
  else if !s || !f.protocolMatches then (s, .incompatible)
  else if !f.pinMatches then (s, .pin)
  else if !f.operationMatches then (s, .method)
  else if !f.versionMatches then (s, .incompatible)
  else if !f.inputValid then (s, .input)
  else if !f.granted then (s, .denied)
  else (s, .delivered)

def mayDescribe (f : Facts) : Bool :=
  f.shape && f.metadata && f.trace && f.dateSyntax && f.future && f.protocols &&
  f.features && f.featureNames && f.coreOffered && f.noRequired

def mayRead (s : Bool) (f : Facts) : Bool :=
  s && f.shape && f.metadata && f.dateSyntax && f.future && f.correlations &&
  f.pinSyntax && f.nameSyntax && f.versionSyntax && f.protocolMatches &&
  f.pinMatches && f.operationMatches && f.versionMatches && f.inputValid && f.granted

theorem bootstrapAcceptance (priority : Bool) (f : Facts) :
    (describe priority f).1 = mayDescribe f ∧
    ((describe priority f).2 = .described ↔ mayDescribe f = true) := by
  simp only [describe, mayDescribe]
  grind (splits := 32)

theorem readAcceptance (s : Bool) (f : Facts) :
    (invoke s f).1 = s ∧ ((invoke s f).2 = .delivered ↔ mayRead s f = true) := by
  simp only [invoke, mayRead]
  grind (splits := 32)

def runOrdinary (step : Bool → Facts → Response) (s : Bool) : List Facts → Bool
  | [] => s
  | f :: fs => runOrdinary step (step s f).1 fs

theorem ordinaryPreserves (step : Bool → Facts → Response)
    (refines : ∀ s f, step s f = invoke s f) (s : Bool) (fs : List Facts) :
    runOrdinary step s fs = s := by
  induction fs generalizing s with
  | nil => rfl
  | cons f fs ih =>
    simp only [runOrdinary, ih, refines, (readAcceptance _ _).1]

def good : Facts :=
  ⟨true, true, true, true, true, true, true, true, true, true,
   true, true, true, true, true, true, true, true, true, true⟩

theorem witnesses :
    describe false good = (true, .described) ∧
    invoke false good = (false, .incompatible) ∧
    invoke true {good with inputValid := false} = (true, .input) ∧
    invoke true {good with granted := false} = (true, .denied) ∧
    invoke true {good with future := false} = (true, .expired) ∧
    invoke true good = (true, .delivered) := by decide

theorem recoverAfterAnyCalls (step : Bool → Facts → Response)
    (refines : ∀ s f, step s f = invoke s f) (history : List Facts) :
    step (runOrdinary step true history) good = (true, .delivered) := by
  rw [ordinaryPreserves step refines, refines]
  rfl

def chooseCore : List String → Option String
  | [] => none
  | head :: tail => if head = "0.1" then some head else chooseCore tail

theorem firstMutuallySupported (offers : List String) :
    chooseCore offers = some "0.1" ↔ "0.1" ∈ offers := by
  induction offers with
  | nil => simp [chooseCore]
  | cons head tail ih =>
    by_cases h : head = "0.1"
    · simp [chooseCore, h]
    · simp [chooseCore, h, ih, Ne.symm h]

def effectiveLimit (localLimit advertised : Nat) := min localLimit advertised

theorem boundedFrame (localLimit advertised n : Nat)
    (bound : n ≤ effectiveLimit localLimit advertised) :
    n ≤ localLimit ∧ n ≤ advertised := by
  exact ⟨Nat.le_trans bound (Nat.min_le_left ..), Nat.le_trans bound (Nat.min_le_right ..)⟩

def answer (requestId : Option String) (v : Verdict) : Option (String × Verdict) :=
  requestId.map (fun rid => (rid, v))

theorem correlation (rid : String) (v : Verdict) :
    answer (some rid) v = some (rid, v) ∧ answer none v = none := by simp [answer]

theorem replyIds (requests : List (String × Verdict)) :
    requests.map (fun p => (answer (some p.1) p.2).map Prod.fst) =
      requests.map (fun p => some p.1) := by simp [answer]

/-- Consume only the matching outstanding ID. The scheduler may present any order. -/
def discharge (pending : String → Bool) (received : String) : String → Bool :=
  fun key => pending key && decide (key ≠ received)

theorem replyOrderIndependent (pending : String → Bool) (a b : String) :
    discharge (discharge pending a) b = discharge (discharge pending b) a := by
  funext key
  simp only [discharge]
  grind

theorem otherRequestRetained (pending : String → Bool) (a b : String) (distinct : a ≠ b) :
    discharge pending b a = pending a := by simp [discharge, distinct]

theorem metadataCannotGrant (s : Bool) (f : Facts) (absent : f.granted = false)
    (validCorrelation : Bool) :
    (invoke s {f with correlations := validCorrelation}).2 ≠ .delivered := by
  intro delivered
  have allowed := (readAcceptance s {f with correlations := validCorrelation}).2.mp delivered
  simp [mayRead, absent] at allowed

inductive FrameEvent
  | eof | unfinished | message (bytes : Nat) (notification : Bool)
  deriving DecidableEq

inductive IOAction
  | stop | reject | silent | writeLF
  deriving DecidableEq

/-- The stdio contract counts the payload preceding LF and reserves stdout for replies. -/
def framing (limit : Nat) : FrameEvent → IOAction
  | .eof => .stop
  | .unfinished => .reject
  | .message n notify => if n > limit then .reject else if notify then .silent else .writeLF

theorem frameBoundary (limit : Nat) :
    framing limit (.message limit false) = .writeLF ∧
    framing limit (.message (limit + 1) false) = .reject ∧
    framing limit (.message limit true) = .silent ∧
    framing limit .unfinished = .reject ∧ framing limit .eof = .stop := by simp [framing]

/-- Forwarding a deadline or a frame quota intersects the active bounds. -/
theorem nestedBounds (budget hop : Nat) : effectiveLimit budget hop ≤ budget :=
  Nat.min_le_left ..

theorem pathBudget (hops : List Nat) (budget : Nat) : hops.foldl effectiveLimit budget ≤ budget := by
  induction hops generalizing budget with
  | nil => exact Nat.le_refl _
  | cons next rest ih =>
    exact Nat.le_trans (ih (effectiveLimit budget next)) (nestedBounds budget next)

end OCSWire
