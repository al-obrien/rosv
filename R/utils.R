#' Extract key OSV information from JSON
#'
#' Use the downloaded JSON dataset from OSV and extract key details on package and versions listed.
#' Packages that do not have a listed version will have a blank space as the default placeholder.
#' This makes it easier for \code{strsplit} to operate on the string in other steps,
#' which will not perform as expected without some value coming after the delimiter.
#'
#' @param input File path to the folder or API response content containing the OSV JSON info
#' @param delim The deliminator to separate the package and version details.
#' @param version_placeholder Value to fill if no versions are listed for package.
extract_vul_info <- function(input, delim = '\t', version_placeholder = ' ') {


  # Load from a file (if it exists), parse accordingly for affected set
  aff_pkgs <- purrr::pluck(jsonlite::read_json(input), 'affected')

  pkg_names <- purrr::map(aff_pkgs, function(x) purrr::pluck(x, 'package', 'name'))
  pkg_versions <- purrr::map(aff_pkgs, function(x) purrr::pluck(x, 'versions'))
  if(length(pkg_versions) == 1 && length(pkg_versions[[1]]) < 1) pkg_versions <- version_placeholder
  unlist(purrr::map2(pkg_names, pkg_versions, function(x,y) paste(x, y, sep = delim)))

}


#' Normalize package name to PyPI expectation
#'
#' Perform some formatting as PyPI is case insensitive and underscore, period, and hyphens
#' as long runs are not recognized (- is same as --).
#'
#' @param pkg_name Vector of package names.
#'
normalize_pypi_pkg <- function(pkg_name) {

  pypi_pattern <- "^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$"
  if(!all(grepl(x = pkg_name, pattern = pypi_pattern, ignore.case = TRUE))) {
    stop('An invalid package name for Python has been provided')
  }

  tolower(gsub(x = pkg_name, "[-_.]+", replacement = "-"))

}


#' Check input against possible ecosystems available
#'
#' Ensures that inputs for ecosystem are valid based upon what is available in OSV database.
#'
#' Will attempt to grab latest file and cache for the session. If cannot access
#' the online version, will use a local copy that is shipped with the package.
#'
#' @param ecosystem Character value for ecosystem(s) to check.
#' @param suppressMessages Boolean value whether or not to suppress any messages.
#'
#' @returns A character vector of the same input if all are valid ecosystem names.
#'
#' @seealso \code{\link{check_ecosystem}}
#'
#' @examples
#' # Passes
#' rosv:::check_ecosystem(c('PyPI', 'CRAN'))
#'
#' # Fails
#' try(rosv:::check_ecosystem(c('notvalid', 'pypi')))
#'
check_ecosystem <- function(ecosystem, suppressMessages = TRUE) {

  ecosystems <- tryCatch({
    fetch_ecosystems(offline = FALSE)
  },
  error = function(e) {
    if(!suppressMessages) message('Using offline version of ecosystem list...')
    fetch_ecosystems(offline = TRUE)
  })

  # Vectorize for batch based checks
  ecosystem <- purrr::map_chr(ecosystem, function(x) match.arg(x, ecosystems$ecosystem, several.ok = FALSE))
  ecosystem
}


#' Fetch all available ecosystems
#'
#' Internal function used to fetch the available ecosystems in the OSV API.
#'
#' The \code{refresh} parameter can be used to force the data to be pulled again
#' even if one is available in the cached location. Since a fresh pull is performed
#' for each R session, it is unlikely that this parameter is required and is primarily
#' reserved for future use if functionality necessitates.
#'
#' @param offline Boolean, determine if use list bundled with package.
#' @param refresh Boolean, force refresh of cache when using online list.
#'
#' @returns A data.frame containing all the ecosystem names available in the OSV database.
#'
#' @seealso \code{\link{check_ecosystem}}
#'
#' @examples
#' rosv:::fetch_ecosystems(offline = TRUE)
#'
fetch_ecosystems <- function(offline = FALSE, refresh = FALSE) {

  time_stamp <- Sys.time()
  date_stamp_hash <- digest::digest(as.Date(time_stamp))
  osv_cache <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), 'ecosystem_list', paste0('ecosystems', '-', date_stamp_hash, '.txt'))

  # Break out if offline
  if(offline) {

    return(osv_ecosystems)

  }

  # If not in cache or force refresh, otherwise use prior pulled
  if(!file.exists(osv_cache) || refresh ) {

    if(!dir.exists(dirname(osv_cache))) dir.create(dirname(osv_cache), recursive = TRUE)

    ecosystems <- utils::read.table('https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt', col.names = 'ecosystem')
    try(utils::write.table(ecosystems, file = osv_cache))

    return(ecosystems)

  } else {

    return(utils::read.table(file = osv_cache, col.names = 'ecosystem'))

  }
}


#' Determine if object is an {{rosv}} type R6 class
#'
#' @param x Object to check.
#' @returns Boolean value based on if \code{x} is an R6 class made by {{rosv}}.
#' @examples
#' is_rosv(RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN'))
#'
#' @export
is_rosv <- function(x) {
  any(inherits(x, 'RosvQuery1'),
      inherits(x, 'RosvQueryBatch'),
      inherits(x, 'RosvVulns'))
}

#' Validate if object is made by {{rosv}}
#' @inheritParams is_rosv
#' @returns Invisibly returns TRUE if validation is successful, otherwise will error.
#' @examples
#' # example code
#' rosv:::validate_rosv(RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN'))
validate_rosv <- function(x) {
  if(!is_rosv(x)) stop('Object is not a class created by {rosv}.')
  invisible(TRUE)
}

#' Create a copy of the {{rosv}} object
#'
#' Since R6 classes have reference semantics, to escape updating original objects,
#' a clone should be made.
#'
#' @param x Object to copy.
#' @param ... Additional parameters sent to R6's clone method.
#' @returns An R6 class object.
#' @examples
#' original_obj <- RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN')
#' new_obj <- copy_rosv(original_obj)
#' @export
copy_rosv <- function(x, ...) {
  validate_rosv(x)
  x$clone(...)
}

#' Retrieve contents field from {{rosv}} R6 object
#' @param x An object made by {{rosv}}
#' @returns Values contained in the content field of the object (data.frame or list).
#' @examples
#' test <- RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN')
#' get_content(test)
#' @export
get_content <- function(x) {
  get_rosv(x, 'content')
}

#' Internal function to assist with extracting details fro {{rosv}} objects
#' @param x An object made by {{rosv}}
#' @param field Name of the field to extract from
get_rosv <- function(x, field) {
  validate_rosv(x)
  x[[field]]
}

# Incomplete... for helping if affected array is nested at different depths in API resp
locate_min_depth <- function(list, target) {

  max_search_depth <- purrr::pluck_depth(list)
  # if(max_search_depth > 100) stop('Will not search larger than 100 steps deep in a list')
  # if(max_search_depth < 1 ) stop('Max search depth must be larger than 0')

  flag <- NULL
  i = 1

  while(is.null(flag)) {
    search_rslt <- unlist(purrr::map_depth(list, i, target, .ragged = TRUE))
    i <- i + 1
    flag <- search_rslt
  }

  for(i in seq(1:max_search_depth)) {

  }

  unlisted <- unlist(list, recursive = TRUE)
  names(unlisted)

  # Assumes each depth has a name...
  split_names <- strsplit(names(unlist(list, recursive = TRUE)), split = '\\.')
  min(unlist(lapply(split_names, function(x) which(x == target))), na.rm = TRUE)
}
