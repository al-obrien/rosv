.onLoad <- function(libname, pkgname) {
  Sys.setenv(ROSV_CACHE_GLOBAL = file.path(tempdir(), 'rosv'))
  dir.create(Sys.getenv('ROSV_CACHE_GLOBAL'), recursive = TRUE)
}

.onUnload <- function(libpath) {
  if(dir.exists(Sys.getenv("ROSV_CACHE_GLOBAL"))) try(unlink(Sys.getenv("ROSV_CACHE_GLOBAL"), TRUE, TRUE, TRUE))
  Sys.unsetenv("ROSV_CACHE_GLOBAL")
}

# Function to enforce httr2 use to remove CRAN note (most was nested in R6 methods)
enforce_httr2_use <- function() {
  httr2::request('dummyURL')
}
