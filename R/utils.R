#' Normalize package name to PyPI expectation
#'
#' Perform package name formatting as PyPI is case insensitive and long runs
#' of underscore, period, and hyphens are not recognized (- is same as --).
#'
#' @param pkg_name Character vector of package names.
#'
#' @returns Character vector of normalized PyPI package names
#'
#' @seealso \href{https://packaging.python.org/en/latest/specifications/name-normalization/}{PyPI Package Normalization}
#'
#' @examples
#' normalize_pypi_pkg(c('Dask', 'TenSorFlow'))
#'
#' @export
normalize_pypi_pkg <- function(pkg_name) {

  pypi_pattern <- "^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$"
  if(!all(grepl(x = pkg_name, pattern = pypi_pattern, ignore.case = TRUE))) {
    stop('An invalid package name for Python has been provided')
  }

  tolower(gsub(x = pkg_name, "[-_.]+", replacement = "-"))

}

#' Reset cached results of OSV calls
#'
#' A thin wrapper around \code{\link[memoise]{forget}} to clear cached results and
#' deletes all cached files under the \code{ROSV_CACHE_GLOBAL} environment variable location.
#'
#' @returns Invisibly returns a logical value of \code{TRUE} if cache cleared without error.
#'
#' @examples
#' clear_osv_cache()
#' @export
clear_osv_cache <- function() {

  # Clear memoise cache
  purrr::walk(list(.osv_query_1_cache, .osv_querybatch_cache, .osv_vulns_cache, .osv_download_cache),
              function(x) memoise::forget(x))

  # Clear download cache (list files/dirs in top of cache, then unlink recursively)
  global_cache_files <- list.files(Sys.getenv("ROSV_CACHE_GLOBAL"), full.names = TRUE)
  if(length(global_cache_files) > 0) unlink(global_cache_files, recursive = TRUE)

  invisible(TRUE)
}


#' Check input against possible ecosystems available
#'
#' Internal function that ensures inputs for ecosystem are valid based upon what
#' is available in the OSV database.
#'
#' Will attempt to grab latest file and cache for the current R session. If session
#' cannot access the online version, it will use a local copy shipped with the package.
#'
#' @param ecosystem Character value for ecosystem(s) to check.
#' @param suppressMessages Boolean value whether or not to suppress any messages.
#'
#' @returns A character vector, the same as input if all are valid ecosystem names.
#'
#' @seealso \code{\link{fetch_ecosystems}}
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
#' @param offline Boolean, determine if using list bundled with package.
#' @param refresh Boolean, force refresh of cache when using online list.
#'
#' @returns A data.frame containing all the ecosystem names available in the OSV database.
#'
#' @seealso \code{\link{check_ecosystem}}
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


#' Is object made from \{rosv\} R6 class
#'
#' Determine if object is an \{rosv\} type R6 class
#'
#' @param x Object to check.
#' @returns Boolean value based on if \code{x} is an R6 class made by \{rosv\}.
#' @examples
#' is_rosv(RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN'))
#'
#' @export
is_rosv <- function(x) {
  any(inherits(x, 'RosvQuery1'),
      inherits(x, 'RosvQueryBatch'),
      inherits(x, 'RosvVulns'),
      inherits(x, 'RosvDownload'))
}

#' Validate if object is made by \{rosv\}
#'
#' Determines if the object is a valid \{rosv\} type.
#'
#' @inheritParams is_rosv
#' @returns Invisibly returns TRUE if validation is successful, otherwise will error.
#' @noRd
validate_rosv <- function(x) {
  if(!is_rosv(x)) stop('Object is not a class created by {rosv}.')
  invisible(TRUE)
}

#' Copy a \{rosv\} object
#'
#' Create a copy of \{rosv\} R6 class objects to ensure original is not also updated with
#' future changes.
#'
#' @details
#' Since R6 classes have reference semantics, to escape updating original objects
#' a clone can be made with this function.
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

#' Retrieve contents field from \{rosv\} R6 object
#'
#' @param x An object made by \{rosv\}.
#'
#' @returns Values contained in the content field of the object (data.frame or list).
#'
#' @examples
#' test <- RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN')
#' get_content(test)
#'
#' @export
get_content <- function(x) {
  get_rosv(x, 'content')
}

#' Extract details from \{rosv\} objects
#'
#' Internal function to assist with extracting details from \{rosv\} objects.
#'
#' @param x An object made by \{rosv\}.
#' @param field Name of the field to extract from.
#' @returns The specified field in the top hierarchy of the R6 class.
#' @noRd
get_rosv <- function(x, field) {
  validate_rosv(x)
  x[[field]]
}


#' Reduce query results to specific package and versions
#'
#' Internal function that helps separate specific package and versions queried from OSV API
#' from other results that may exist for a vulnerability. This ensures results returned
#' are specific to the subset defined by the query and does not add other packages and versions
#' that may have been impacted by the same vulnerability.
#'
#' @details
#' To perform the filtering, base R \code{merge()} is used. Column and row order are preserved
#' even if some rows are dropped. Errors will be thrown if the user attempts to filter by \code{NA} and specific versions
#' for a combination of a package and ecosystem. With this enforced, it is also easier to keep all rows with \code{NA} versions listed
#' and reduce any versions to those specified in the parameters.
#'
#' @param data Query result in data.frame format.
#' @inheritParams osv_query
#'
#' @returns A data.frame with filtered results.
#' @noRd
filter_affected <- function(data, name = NULL, ecosystem = NULL, version = NULL) {

  if(any(is.na(name)) | any(is.na(ecosystem))) warning('Some package and/or ecosystem names were NA')

  # Inner join on pkg and ecosystem
  colname_index <- colnames(data)
  data$index <- 1:nrow(data)
  data <- merge(data, unique(data.frame(name = name, ecosystem = ecosystem)))

  # Handle if version provided
  if(!is.null(version)) {
    data <- split(data, is.na(data$versions)) # if NA is in response, handle separate
    ref_df <- unique(data.frame(name = name, ecosystem = ecosystem, versions = version))

    # Check is someone mixed version filter and all
    mixcheck <- sapply(split(ref_df$versions, list(ref_df$name, ref_df$ecosystem)),
                       function(x) any(is.na(x)) & any(!is.na(x)))
    if(any(mixcheck)) stop('Cannot mix NA with specific versions for a particular package and ecosystem combination.')

    # Keep if NA in search
    ref_df <- split(ref_df, is.na(ref_df$versions))

    data <- rbind(if(!is.null(data$`TRUE`)) data$`TRUE` else NULL,
                  if(is.null(ref_df$`FALSE`) || is.null(data$`FALSE`)) NULL else merge(data$`FALSE`, ref_df$`FALSE`),
                  if(is.null(ref_df$`TRUE`) || is.null(data$`FALSE`)) NULL  else merge(data$`FALSE`, ref_df$`TRUE`[,c('name', 'ecosystem')]))
  }

  data <- data[order(data$index),]
  data$index <- NULL
  data <- data[, colname_index]

  data

}

