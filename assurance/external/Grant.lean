import Std

namespace ExternalGrant

inductive Term where
  | imported | offered | band (older newer : Term)
deriving DecidableEq, Repr

inductive Op where
  | imported | offered | band
deriving DecidableEq, Repr

def denote (x y : BitVec 32) : Term → BitVec 32
  | .imported => x
  | .offered => y
  | .band a b => denote x y a &&& denote x y b

def symbolic : Op → List Term → Option (List Term)
  | .imported, s => some (.imported :: s)
  | .offered, s => some (.offered :: s)
  | .band, b :: a :: tail => some (.band a b :: tail)
  | .band, _ => none

def instruction (x y : BitVec 32) : Op → List (BitVec 32) → Option (List (BitVec 32))
  | .imported, s => some (x :: s)
  | .offered, s => some (y :: s)
  | .band, b :: a :: tail => some ((a &&& b) :: tail)
  | .band, _ => none

def execute (x y : BitVec 32) : List Op → List (BitVec 32) → Option (List (BitVec 32))
  | [], s => some s
  | op :: ops, s => (instruction x y op s).bind (execute x y ops)

def certify : List Op → List Term → List (List Term) → Option (List Term)
  | [], s, [] => some s
  | op :: ops, s, proposed :: more =>
    if symbolic op s = some proposed then certify ops proposed more else none
  | _, _, _ => none

theorem stepSound (x y : BitVec 32) (op : Op) (s : List Term) :
    instruction x y op (s.map (denote x y)) = (symbolic op s).map (List.map (denote x y)) := by
  cases op with
  | imported => rfl
  | offered => rfl
  | band =>
    cases s with
    | nil => rfl
    | cons b tail => cases tail <;> rfl

theorem certificateSound (x y : BitVec 32) (ops : List Op) (stack : List Term)
    (frames : List (List Term)) (final : List Term) (h : certify ops stack frames = some final) :
    execute x y ops (stack.map (denote x y)) = some (final.map (denote x y)) := by
  induction ops generalizing stack frames with
  | nil =>
    cases frames with
    | nil => simp [certify] at h; subst final; rfl
    | cons _ _ => simp [certify] at h
  | cons op ops ih =>
    cases frames with
    | nil => simp [certify] at h
    | cons next tail =>
      by_cases hs : symbolic op stack = some next
      · simp only [certify, hs, ite_true] at h
        have concrete := stepSound x y op stack
        rw [hs] at concrete
        simp only [execute, concrete, Option.map, Option.bind]
        exact ih next tail h
      · simp [certify, hs] at h

-- This byte-level subset has one function, signature (i32,i32)->i32, one
-- initial memory page and exports memory and function index zero as ocs_grant.
-- It has no imports, start function or local variables.
def modulePrefix : List Nat :=
  [0,97,115,109,1,0,0,0, 1,7,1,96,2,127,127,1,127, 3,2,1,0, 5,3,1,0,1,
   7,22,2,6,109,101,109,111,114,121,2,0,9,111,99,115,95,103,114,97,110,116,0,0]

def decodeBody : List Nat → Option (List Op)
  | [11] => some []
  | 32 :: 0 :: tail => (decodeBody tail).map (Op.imported :: ·)
  | 32 :: 1 :: tail => (decodeBody tail).map (Op.offered :: ·)
  | 113 :: tail => (decodeBody tail).map (Op.band :: ·)
  | _ => none

def decode (bytes : List Nat) : Option (List Op) :=
  if bytes.take modulePrefix.length ≠ modulePrefix then none else
    match bytes.drop modulePrefix.length with
    | 10 :: sectionSize :: 1 :: bodySize :: 0 :: code =>
      if sectionSize = code.length+3 ∧ bodySize = code.length+1 ∧ sectionSize < 128 then decodeBody code else none
    | _ => none

def Statement (artifact : List Nat) : Prop :=
  ∃ ops, decode artifact = some ops ∧ ∀ (x y : BitVec 32), execute x y ops [] = some [x &&& y]

end ExternalGrant
