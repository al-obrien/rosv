.onLoad <- function(libname, pkgname) {
  Sys.setenv(ROSV_CACHE_GLOBAL = file.path(tempdir(), 'rosv'))
  dir.create(Sys.getenv('ROSV_CACHE_GLOBAL'), recursive = TRUE, showWarnings = FALSE)

  # Caching versions generated upon load.
  .osv_query_1_cache <<- memoise::memoise(.osv_query_1)
  .osv_querybatch_cache <<- memoise::memoise(.osv_querybatch)
  .osv_vulns_cache <<- memoise::memoise(.osv_vulns)
}

.onUnload <- function(libpath) {
  if(dir.exists(Sys.getenv("ROSV_CACHE_GLOBAL"))) try(unlink(Sys.getenv("ROSV_CACHE_GLOBAL"), TRUE, TRUE, TRUE))
  Sys.unsetenv("ROSV_CACHE_GLOBAL")
}

#' Enforce httr2 use to remove CRAN note
#'
#' Function to enforce httr2 use to remove CRAN note which occurred since most of
#' these were embedded within R6 methods and not discovered automatically by R CMD Checks.
#'
#' @returns A dummy http request.
#'
#' @noRd
enforce_httr2_use <- function() {
  httr2::request('dummyURL')
}
