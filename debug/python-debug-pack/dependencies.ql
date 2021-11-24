import python
import semmle.python.dependencies.TechInventory

predicate src_package_count(ExternalPackage package, int total) {
  total =
    strictcount(AstNode src |
      dependency(src, package) and exists(src.getLocation().getFile().getRelativePath())
    )
}

string make_name(ExternalPackage package) {
  result = package.getName() + "@" + package.getVersion()
  or
  not exists(package.getVersion()) and
  result = package.getName() + "@unknown"
}

from int total, string entity, ExternalPackage package
where
  src_package_count(package, total) and
  entity = make_name(package)
select entity, total order by total desc
