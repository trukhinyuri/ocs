import Contract
import Extracted

namespace OCSWire

theorem pythonReadRefines (s : Bool) (f : Facts) :
    Extracted.pythonRead s f = invoke s f := by
  simp only [Extracted.pythonRead, invoke]
  grind (splits := 40)

theorem goReadRefines (s : Bool) (f : Facts) :
    Extracted.goRead s f = invoke s f := by
  simp only [Extracted.goRead, invoke]
  grind (splits := 40)

theorem pythonDescribeRefines (s : Bool) (f : Facts) :
    Extracted.pythonDescribe s f = describe false f := by
  simp only [Extracted.pythonDescribe, describe]
  grind (splits := 40)

theorem goDescribeRefines (s : Bool) (f : Facts) :
    Extracted.goDescribe s f = describe true f := by
  simp only [Extracted.goDescribe, describe]
  grind (splits := 40)

theorem pythonRecovers (history : List Facts) :
    Extracted.pythonRead (runOrdinary Extracted.pythonRead true history) good =
      (true, .delivered) := recoverAfterAnyCalls _ pythonReadRefines history

theorem goRecovers (history : List Facts) :
    Extracted.goRead (runOrdinary Extracted.goRead true history) good =
      (true, .delivered) := recoverAfterAnyCalls _ goReadRefines history

theorem pythonUnknown (s : Bool) (f : Facts) :
    Extracted.pythonOther s f = (s, .method) := by rfl

theorem goUnknown (s : Bool) (f : Facts) :
    Extracted.goOther s f = (s, .method) := by rfl

theorem pythonStdio (event : FrameEvent) :
    Extracted.pythonFrame event = framing 1048576 event := by cases event <;> rfl

theorem goStdio (event : FrameEvent) :
    Extracted.goFrame event = framing 1048576 event := by cases event <;> rfl

#print axioms pythonStdio
#print axioms goStdio
#print axioms frameBoundary
#print axioms nestedBounds
#print axioms pathBudget
#print axioms replyOrderIndependent
#print axioms otherRequestRetained
#print axioms metadataCannotGrant
#print axioms bootstrapAcceptance
#print axioms readAcceptance
#print axioms ordinaryPreserves
#print axioms witnesses
#print axioms firstMutuallySupported
#print axioms boundedFrame
#print axioms correlation
#print axioms replyIds
#print axioms pythonReadRefines
#print axioms goReadRefines
#print axioms pythonDescribeRefines
#print axioms goDescribeRefines
#print axioms pythonRecovers
#print axioms goRecovers
#print axioms pythonUnknown
#print axioms goUnknown

end OCSWire
