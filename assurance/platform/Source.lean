import Platform
import Concrete
set_option autoImplicit false

namespace Platform

theorem nativeSource (p a o i hard : Bool) :
    Concrete.admit_native p a o i hard = nativeAdmission p a o i hard := by
  cases p <;> cases a <;> cases o <;> cases i <;> cases hard <;> rfl

theorem writerSource (f : Fence) (owner writer epoch : Nat) :
    Concrete.may_write (owner == f.owner) (writer == f.activeWriter) f.epoch epoch =
      mayWrite f owner writer epoch := by
  unfold Concrete.may_write mayWrite
  rw [BEq.comm (a := f.epoch) (b := epoch)]

theorem cellSource (q : Queue) (g t : Nat) :
    Concrete.enter_cell q.active q.tenant g t = decide (q.active < g ∧ q.tenant < t) := by
  by_cases a : q.active < g <;> by_cases b : q.tenant < t <;> simp [Concrete.enter_cell, a, b]

end Platform
