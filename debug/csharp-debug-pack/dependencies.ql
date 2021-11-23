import csharp

/**
 * Finds any type use by each source element. Only source declarations
 * are considered, not constructed types and methods.
 */
Type getATypeUse(Element elt) {
  exists(Variable v | elt = v and v.isSourceDeclaration() and result = v.getType())
  or
  exists(ValueOrRefType t | elt = t and t.isSourceDeclaration() and result = t.getABaseType())
  or
  exists(Property p | elt = p and p.isSourceDeclaration() and result = p.getType())
  or
  exists(Method m | elt = m and m.isSourceDeclaration() and result = m.getReturnType())
  or
  result = elt.(Expr).getType()
  or
  result = elt.(Attribute).getType()
  or
  result = getATypeUse(elt).(ConstructedType).getATypeArgument()
  or
  result = elt.(MethodCall).getTarget().(ConstructedMethod).getATypeArgument()
}

predicate getElementInFile(File file, Element elt, Assembly assembly) {
  elt.getLocation().getFile() = file and
  assembly = getATypeUse(elt).getLocation()
}

predicate excludedAssembly(Assembly assembly) {
  assembly.getName() = "mscorlib"
  or
  assembly.getName() = "System"
  or
  assembly.getName() = "System.Core"
  or
  assembly.getName() = "System.Private.CoreLib"
}

/**
 * Generate the table of dependencies for the query.
 */
predicate externalDependencies(string encodedDependency, int num) {
  num =
    strictcount(Element e |
      // Quantify over `assembly` inside the `strictcount`, to avoid multiple entries for
      // assemblies with the same name and version
      exists(Assembly assembly, File f |
        f.fromSource() and
        getElementInFile(f, e, assembly) and
        not excludedAssembly(assembly) and
        encodedDependency = assembly.getName() + "@" + assembly.getVersion()
      )
    )
}

from int num, string encodedDependency
where externalDependencies(encodedDependency, num)
select encodedDependency, num order by num desc
