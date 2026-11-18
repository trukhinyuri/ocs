import Interaction
import Concrete
set_option autoImplicit false

namespace Interaction

theorem admitSource (i a b live own : Bool) (cur seen : Nat) :
    Concrete.admit i a b live own cur seen = admit i a b live own cur seen := by
  cases i <;> cases a <;> cases b <;> cases live <;> cases own <;> rfl

theorem grantSource (parent exp imp scopeOK : Bool) :
    Concrete.grant parent exp imp scopeOK = grant parent exp imp scopeOK := by
  cases parent <;> cases exp <;> cases imp <;> cases scopeOK <;> rfl

theorem reserveSource (budget share : Nat) : Concrete.reserve budget share = reserve budget share := by
  by_cases h : share ≤ budget <;> simp [Concrete.reserve, reserve, h]

theorem ackSource (old asked high : Nat) : Concrete.ack_position old asked high = ack old asked high := by
  by_cases a : old ≤ asked <;> by_cases b : asked ≤ high <;> simp [Concrete.ack_position, ack, a, b]

theorem continueSource (waiting owner : Bool) (rev expected : Nat) :
    Concrete.can_continue waiting owner rev expected = canContinue waiting owner rev expected := by
  cases waiting <;> cases owner <;> rfl

theorem pageSource (len off budget : Nat) : Concrete.page_size len off budget = pageSize len off budget := by rfl

def packed (s : Stream) := (s.credit, s.sent, s.granted, s.remaining, s.finals)
def opcode : Action → Nat | .give _ => 0 | .send => 1 | .finish => 2
def extra : Action → Nat | .give n => n | .send => 0 | .finish => 0

theorem streamSource (s : Stream) (a : Action) (owner : Bool) (cap : Nat) :
    Concrete.stream_step (opcode a) owner s.credit s.sent s.granted s.remaining s.finals (extra a) cap =
    packed (tick s a owner cap) := by
  cases owner <;> by_cases live : s.finals = 0
  all_goals cases a with
  | give n =>
    by_cases pos : 0 < n <;> by_cases room : s.credit + n ≤ cap <;>
      simp [Concrete.stream_step, tick, opcode, extra, packed, live, pos, room]
  | send =>
    by_cases cr : 0 < s.credit <;> by_cases work : 0 < s.remaining <;>
      simp [Concrete.stream_step, tick, opcode, extra, packed, live, cr, work]
  | finish => simp [Concrete.stream_step, tick, opcode, extra, packed, live]


theorem surfaceSource (v version d a g : Bool) :
    Concrete.surface_eligible v version d a g = surfaceEligible v version d a g := by
  cases v <;> cases version <;> cases d <;> cases a <;> cases g <;> rfl

theorem callbackSource (serial sameChannel permitted : Bool) :
    Concrete.callback_safe serial sameChannel permitted = callbackAllowed serial sameChannel permitted := by
  cases serial <;> cases sameChannel <;> cases permitted <;> rfl

end Interaction
