.onLoad <- function(libname, pkgname) {
  Sys.setenv(ROSV_CACHE_GLOBAL = file.path(tempdir(), 'rosv'))
}

.onUnload <- function(libpath) {
  if(dir.exists(Sys.getenv("ROSV_CACHE_GLOBAL"))) try(unlink(Sys.getenv("ROSV_CACHE_GLOBAL"), TRUE, TRUE, TRUE))
  Sys.unsetenv("ROSV_CACHE_GLOBAL")
}
