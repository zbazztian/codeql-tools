import semmle.javascript.dataflow.DataFlow

abstract class DebugNode extends DataFlow::Node {
  abstract string getConfigName();

  abstract string getNodeType();
}

class DebugSource extends DebugNode {
  string configName;

  DebugSource() {
    configName.(DataFlow::Configuration).isSource(this)
    or
    configName.(DataFlow::Configuration).isSource(this, _)
  }

  override string getConfigName() { result = configName }

  override string getNodeType() { result = "source" }
}

class DebugSink extends DebugNode {
  string configName;

  DebugSink() {
    configName.(DataFlow::Configuration).isSink(this)
    or
    configName.(DataFlow::Configuration).isSink(this, _)
  }

  override string getConfigName() { result = configName }

  override string getNodeType() { result = "sink" }
}

string configNames() { result instanceof DataFlow::Configuration }

string nodeTypes() { result = ["source", "sink"] }

DebugNode debugNodes(string configName, string type) {
  configName = result.getConfigName() and type = result.getNodeType()
}

query predicate sources(string loc, string configName) {
  loc = any(DebugSource ds | ds.getConfigName() = configName).getFile().getRelativePath()
}

query predicate sinks(string loc, string configName) {
  loc = any(DebugSink ds | ds.getConfigName() = configName).getFile().getRelativePath()
}

query predicate source_and_sink_counts(string configName, int source_count, int sink_count) {
  configName = configNames() and
  source_count = count(DebugSource ds | ds.getConfigName() = configName) and
  sink_count = count(DebugSink ds | ds.getConfigName() = configName)
}
