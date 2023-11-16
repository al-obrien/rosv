#' Parse renv LOCK file
#'
#' Parse the LOCK file containing R packages and versions at the provided location.
#'
#' @param dir Directory of project with LOCK file.
#' @param file_name Name of LOCK file (default: 'renv.lock').
#' @param as.data.frame Boolean value, determine if parsed content is in a data.frame format
#'
#' @returns Package and version information as a list of data.frame.
#'
#' @noRd
parse_renv_lock <- function(dir = '.', file_name = 'renv.lock', as.data.frame = TRUE) {

  lock_location <- file.path(dir, file_name)
  stopifnot(file.exists(lock_location))

  lock_n_load <- jsonlite::fromJSON(lock_location)[['Packages']]

  if(as.data.frame) {
    purrr::list_rbind(purrr::map(lock_n_load,
                                 function(x) {
                                   data.frame(name = purrr::pluck(x, 'Package'),
                                              version = purrr::pluck(x, 'Version'),
                                              ecosystem = 'CRAN')
                                 })
    )
  } else {
    purrr::map(lock_n_load,
               function(x) {
                 c(name = purrr::pluck(x, 'Package'),
                   version = purrr::pluck(x, 'Version'),
                   ecosystem = 'CRAN')
               })
  }
}

#' Parse R installed libraries
#'
#' Parse and return installed libraries discovered at the library paths.
#'
#' @details
#' Default path will be from results of \code{.libPaths()}.
#'
#'
#' @param ... Parameters for \code{\link[utils]{installed.packages()}}.
#'
#' @returns Package and version information as a data.frame.
#'
#' @noRd
parse_r_libpath <- function(...) {
  rlibs <- utils::installed.packages(...)[,c('Package', 'Version')]
  rlibs <- as.data.frame(rlibs, row.names = FALSE)
  colnames(rlibs) <- c('name', 'version')
  rlibs <- cbind(rlibs, ecosystem = 'CRAN')
  rlibs
}


#' Scan renv LOCK file for vulnerabilities
#'
#' Parse and scan the renv LOCK file at specified location for vulnerabilities in the OSV database.
#'
#' @inheritParams parse_renv_lock
#'
#' @returns A data.frame specifying which packages are vulnerable or not.
#'
#' @noRd
osv_scan_renv <- function(dir = '.', as.data.frame = TRUE) {
  pkg_data <- parse_renv_lock(dir = dir, as.data.frame = as.data.frame)
  pkg_data$is_vul <- is_pkg_vulnerable(name = pkg_data$name, ecosystem = pkg_data$ecosystem, version = pkg_data$version)
  pkg_data
}


#' Scan installed R libraries for vulnerabilities
#'
#' Parse and scan installed R libraries for vulnerabilities in the OSV database.
#'
#' @inheritParams parse_r_libpath
#'
#' @returns A data.frame specifying which packages are vulnerable or not.
#'
#' @noRd
osv_scan_r_libpath <- function(...) {
  pkg_data <- parse_r_libpath(...)
  pkg_data$is_vul <- is_pkg_vulnerable(name = pkg_data$name, ecosystem = pkg_data$ecosystem, version = pkg_data$version)
  pkg_data
}


#' Scan an R project for vulnerabilities
#'
#' Parse and scan LOCK files and installed packages for package vulnerabilities in the OSV database.
#'
#' @param dir Project location.
#' @param sort_by_vul Boolean value, to determine if vulnerable packages should be listed at top.
#'
#' @returns A data.frame specifying which packages are vulnerable or not.
#'
#' @noRd
osv_scan_r_project <- function(dir = '.', sort_by_vul = TRUE) {

  # Attempt each and bind
  lock_pkgs <- tryCatch(parse_renv_lock(dir = dir),
                        error = function(e) {warning(e); return(NULL)})

  pkg_data <- unique(rbind(parse_r_libpath(), lock_pkgs))

  pkg_data$is_vul <- is_pkg_vulnerable(name = pkg_data$name, ecosystem = pkg_data$ecosystem, version = pkg_data$version)

  if(sort_by_vul) {
    pkg_data[order(-pkg_data$is_vul, pkg_data$name, pkg_data$version),]
  } else{
    pkg_data[order(pkg_data$name, pkg_data$version),]
  }
}


#' Use OSV database to scan for vulnerabilities
#'
#' Scan project based upon specified mode to determine if any vulnerable packages are detected.
#'
#' @details
#' The available scanning modes are: 'r_project', 'renv', and 'r_libath'. The 'r_libpath' mode
#' simply performs all R project related scans at once. Emphasis is placed on scans of R related content.
#' Additional parsing and scanning modes will be added over time as needed. If a mode does not exist for
#' a particular purpose, alternate functions such as \code{is_pkg_vulnerable()} can be used with any list of
#' package names for ecosystems available in the OSV database.
#'
#' @seealso \code{\link{is_pkg_vulnerable}}
#'
#' @param mode The kind of scan to perform.
#' @param ... Parameters passed to specific underlying functions for mode selected.
#'
#' @returns A data.frame specifying which packages are vulnerable or not.
#'
#' @examplesIf interactive()
#' osv_scan('r_libpath')
#'
#' @export
osv_scan <- function(mode, ...) {
  mode <- match.arg(mode,
                    choices = c('r_project', 'renv', 'r_libpath'),
                    several.ok = FALSE)
  switch(mode,
         r_project = osv_scan_r_project(...),
         renv = osv_scan_renv(...),
         r_libpath = osv_scan_r_libpath(...))
}

