import Contract
import Extracted

namespace OCSWire
/- The normal sealed host cannot dispatch after describe if the reported
   package, revision or digest differs. Other checks may independently refuse. -/
theorem pythonHostBinding (id revision digest others : Bool)
    (sent : Extracted.pythonHostSends id revision digest others = true) :
    id = true ∧ revision = true ∧ digest = true := by
  simp only [Extracted.pythonHostSends] at sent
  grind

theorem goHostBinding (id revision digest others : Bool)
    (sent : Extracted.goHostSends id revision digest others = true) :
    id = true ∧ revision = true ∧ digest = true := by
  simp only [Extracted.goHostSends] at sent
  grind

theorem reachableHostGate :
    Extracted.pythonHostSends true true true true = true ∧
    Extracted.goHostSends true true true true = true ∧
    Extracted.pythonHostSends true true false true = false ∧
    Extracted.goHostSends true true false true = false := by decide

#print axioms pythonHostBinding
#print axioms goHostBinding
#print axioms reachableHostGate
end OCSWire
