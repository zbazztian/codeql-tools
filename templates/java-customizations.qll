import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.FlowSteps


// additional sources: Consider return values of ServletRequest methods to be tainted (potentially noisy)
class ServletRequestSource extends RemoteFlowSource {
  ServletRequestSource() {
    exists(Method m |
      this.asExpr().(MethodAccess).getMethod() = m and
      m.getDeclaringType().getAnAncestor*().getQualifiedName() = "javax.servlet.ServletRequest"
    )
  }

  override string getSourceType() { result = "ServletRequest method return value" }
}


// Additional taint step: If an object is tainted, so are its methods' return values
class TaintedObjectMA extends AdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    node1.asExpr() = node2.asExpr().(MethodAccess).getQualifier()
  }
}

// Additional taint step: If an argument to a constructor is tainted, so is the constructed object
class TaintedConstructorArg extends AdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2) {
    node1.asExpr() = node2.asExpr().(ConstructorCall).getAnArgument()
  }
}


/////////////////////////// CUSTOMIZE HERE ////////////////////////////////////////////////////
/*
string taintedCalls() {
  result = [
    "org.apache.ofbiz.base.util.UtilIO.copy", // all invocations of this method return tainted data
    "%.copy"                                  // ditto, just matching on the callable's name
  ]
}

string taintedParams() {
  result = [
    "org.apache.ofbiz.base.util.UtilIO.copy.0", // exact match with exact index
    "com.org.Type.myMethod.1", // ditto
    "%.myMethod.1", // match just on the name of a method and an index
    "%.myMethod.%" // match just on the name of a method and all its parameters
  ]
}

string paramsWhichPassTaintThroughToTheReturnValue() {
  result = [
    "com.org.Type.myMethod.0", // taint passes from first parameter to return value
    "com.org.OtherType.myMethod.1", // ditto, but for 2nd parameter
    "%.myMethod.0", // use placeholder
    "%.myMethod.%", // use placeholder for name and index
    "%.myMethod.-1" // taint passes from qualifier to return value
  ]
}
///////////////////////////////////////////////////////////////////////////////////////////////

string callableSignature(Callable c) {
  result = c.getDeclaringType().getQualifiedName() + "." + c.getName()
}

string paramSignature(Parameter p) {
  result = callableSignature(p.getCallable()) + "." + p.getPosition()
}

string qualifierSignature(Callable c) {
  result = c.getDeclaringType().getQualifiedName() + "." + c.getName() + ".-1"
}

class TaintedParameters extends RemoteFlowSource {
  TaintedParameters() { paramSignature(this.asParameter()).matches(taintedParams()) }

  override string getSourceType() { result = "Custom tainted parameter" }
}

class TaintedCalls extends RemoteFlowSource {
  TaintedCalls() { callableSignature(this.asExpr().(Call).getCallee()).matches(taintedCalls()) }

  override string getSourceType() { result = "Custom tainted call" }
}

class CallablesWhichReturnTaintFromParams extends TaintPreservingCallable {
  int paramIdx;

  CallablesWhichReturnTaintFromParams() {
    paramSignature(this.getParameter(paramIdx))
        .matches(paramsWhichPassTaintThroughToTheReturnValue())
    or
    qualifierSignature(this).matches(paramsWhichPassTaintThroughToTheReturnValue()) and
    paramIdx = -1
  }

  override predicate returnsTaintFrom(int arg) { arg = paramIdx }
}
*/


/*
class ATS extends AdditionalTaintStep {
  override predicate step(DataFlow::Node node1, DataFlow::Node node2){
  }
}
*/

