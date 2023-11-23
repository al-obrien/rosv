#' Query OSV API for individual package vulnerabilities
#'
#' Will connect to OSV API and query vulnerabilities from the specified packages.
#' Unlike the other query functions, \code{osv_query} will only return content and not
#' the response object. By default all vulnerabilities are returned for any versions of the package flagged
#' in OSV. This can be subset manually or via the parameter \code{all_affected}.
#'
#' @details
#' Since the \href{https://google.github.io/osv.dev/post-v1-query/}{query} and
#' \href{https://google.github.io/osv.dev/post-v1-querybatch/}{batchquery} API endpoints have different outputs, this
#' function will align their contents to be a list of vulnerabilities. For 'query' this
#' meant flattening the returned list once; for 'batchquery' the returned IDs are used to fetch additional
#' vulnerability information and then flattened to a list.
#'
#' If only an \code{ecosystem} parameter is provided, all vulnerabilities for that selection
#' will be downloaded from the OSV database and parsed into a tidied table. Since some
#' vulnerabilities can exist across ecosystems, \code{all_affected} may need to be set to \code{FALSE}.
#'
#' Since the OSV database is organized by vulnerability, the returned content may have duplicate
#' package details as the same package, and possibly its version, may occur within several different
#' reported vulnerabilities. To avoid this behaviour, set the \code{all_affected} parameter to \code{FALSE}.
#'
#' Due to variations in formatting from the OSV API, not all responses have versions associated in
#' the response but instead use ranges. Filtering currently does not apply to this field and may return
#' all versions affected within the ranges. If you suspect ranges are used instead of specific version codes,
#' examine the response object using lower-level functions like \code{osv_query_1()}.
#'
#' To speed up the process for large ecosystems you can set \code{future::plan()}
#' for parallelization; this will be respected via the \code{furrr} package. The default will be to run sequentially.
#' There are performance impacts to allow for mixed ecosystems to be queried. For packages with many vulnerabilities,
#' it can be faster to perform those separately so all vulnerabilities can be pulled at once and not individually. Alternative
#' approaches may be implemented in future versions.
#'
#' @param name Character vector of package names.
#' @param version Character vector of package versions, \code{NA} if ignoring versions.
#' @param ecosystem Character vector of ecosystem(s) within which the package(s) exist.
#' @param all_affected Boolean value, if \code{TRUE} return all package results found per vulnerability discovered.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#' @param ... Any other parameters to pass to nested functions.
#'
#' @returns A data.frame with query results parsed.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @examplesIf interactive()
#'
#' # Single package
#' pkg_vul <- osv_query('dask', ecosystem = 'PyPI')
#'
#' # Batch query
#' name_vec <- c('dask', 'dash')
#' ecosystem_vec <- rep('PyPI', length(name_vec))
#' pkg_vul <- osv_query(name_vec, ecosystem = ecosystem_vec)
#'
#' @export
osv_query <- function(name = NULL, version = NULL, ecosystem = NULL, all_affected = TRUE, cache = TRUE, ...) {

  # Checks which may be specific to osv_query and not underlying lower level functions
  if(is.null(ecosystem)) stop('An ecosystem must be provided')
  if(is.null(name) & !is.null(version)) stop('Name parameter should be set if also providing versions')

  # Batch method...
  if(length(name) > 1) {
    batch_vulns <- get_content(osv_querybatch(name = name,
                                              version = version,
                                              ecosystem = ecosystem,
                                              cache = cache,
                                              ...))

    # Grab IDs for all Vulns and return the more details vulns info
    batch_vulns <- get_content(osv_vulns(batch_vulns$id, cache = cache))


    if(!all_affected) {
      batch_vulns <- filter_affected(batch_vulns, name, ecosystem, version)
    }

    return(structure(batch_vulns, class = c('rosv_query', 'data.frame')))

  # Query 1 method...
  } else if(length(name) == 1) {

    # Align by pre-plucking the vulnerability label
    query1 <- get_content(osv_query_1(name = name,
                                      version = version,
                                      ecosystem = ecosystem,
                                      cache = cache,
                                      ...))

    if(!all_affected) {
      query1 <- filter_affected(query1, name, ecosystem, version)
    }

    return(structure(query1, class = c('rosv_query', 'data.frame')))

  # Download ALL method
  } else if((is.null(name) || length(name) == 0) && !is.null(ecosystem)) {

    message('Grabbing all vulnerabilities for ecosystem (', ecosystem, '), this may take a moment...')

    download_all <- get_content(osv_download(ecosystem = ecosystem, cache = cache, ...))

    if(!all_affected) {
      download_all <- download_all[download_all$ecosystem == ecosystem,]
    }

    return(structure(download_all, class = c('rosv_query', 'data.frame')))

  }
}


#' Detect if package within ecosystem has reported vulnerabilities
#'
#' Search the OSV database, by package name and its respective ecosystem, to determine
#' if a vulnerability has ever been listed. If a package has been listed as impacted by
#' a vulnerability this may warrant further queries to investigate specific versions
#' that have been affected.
#'
#' @inheritParams osv_query
#' @returns A named vector of logical values indicating vulnerabilities.
#'
#' @examplesIf interactive()
#' is_pkg_vulnerable(c('dask', 'dplyr'), c('PyPI', 'CRAN'))
#'
#' @export
is_pkg_vulnerable <- function(name, ecosystem, ...) {

  # Initialize FALSE vector
  results_vec <- logical(length = length(name))

  # Find TRUE locations
  index <- get_content(osv_querybatch(name = name,
                                      ecosystem = ecosystem,
                                      ...))

  results_vec[unique(as.integer(index$result))] <- TRUE
  names(results_vec) <- name
  results_vec

}

#' Count the number of reported vulnerabilities
#'
#' Search the OSV database, by package name and its respective ecosystem, and count the number
#' of discovered vulnerabilities listed.
#'
#' @inheritParams osv_query
#' @returns A named vector of numeric values indicating vulnerabilities.
#'
#' @examplesIf interactive()
#' osv_count_vulns(c('dask', 'dplyr'), c('PyPI', 'CRAN'))
#'
#' @export
osv_count_vulns <- function(name, ecosystem, ...) {

  # Initialize 0 vector
  results_vec <- integer(length = length(name))

  # Find vulns
  index <- get_content(osv_querybatch(name = name,
                                      ecosystem = ecosystem,
                                      ...))

  vulns_count <- tapply(index$id,
                        index$result,
                        FUN = function(x) length(unique(x)))

  results_vec[unique(as.integer(index$result))] <- vulns_count
  names(results_vec) <- name
  results_vec

}

