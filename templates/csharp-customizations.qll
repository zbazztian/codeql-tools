import csharp
import semmle.code.csharp.security.dataflow.flowsources.Remote
import semmle.code.csharp.security.dataflow.SqlInjection::SqlInjection as SqlInjection

/////////////////////////// CUSTOMIZE HERE ////////////////////////////////////////////////////
string taintedCalls() {
  result = [
    "System.Environment.GetEnvironmentVariable", // all invocations of this method return tainted data
    "%.copy"                                     // ditto, just matching on the callable's name
  ]
}

string taintedParams() {
  result = [
    "Dapper.Samples.Advanced.SQLServerFeatures.PrepareDatabase:0", // exact match with exact index
    "com.org.Type.myMethod:1", // ditto
    "%.myMethod:1", // match just on the name of a method and an index
    "%.myMethod:%" // match just on the name of a method and all its parameters
  ]
}

// call arguments pertaining to these parameters will be treated as sql injection sinks
string sqlInjectionSinks() {
  result = [
    "Dapper.SqlMapper.Query%:1",
    "%Execute%:1"
  ]
}

///////////////////////////////////////////////////////////////////////////////////////////////
string paramSignature(Parameter p) {
  result = p.getCallable().getQualifiedName() + ":" + p.getPosition()
}

class TaintedParameters extends RemoteFlowSource {
  TaintedParameters() { paramSignature(this.asParameter()).matches(taintedParams()) }

  override string getSourceType() { result = "Custom tainted parameter" }
}

class TaintedCalls extends RemoteFlowSource {
  TaintedCalls() { this.asExpr().(Call).getTarget().getQualifiedName().matches(taintedCalls()) }

  override string getSourceType() { result = "Custom tainted call" }
}

class SqlInjectionSink extends SqlInjection::Sink {
  SqlInjectionSink() {
    exists(Parameter p | paramSignature(p).matches(sqlInjectionSinks()) |
      this.asExpr() = p.getCallable().getACall().getArgumentForParameter(p)
    )
  }
}
