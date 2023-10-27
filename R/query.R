#' Download helper for OSV data
#'
#' Helper function to assist in downloading vulnerabilities information from OSV database.
#'
#' Any ecosystems listed \href{here}{'https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt'} can be downloaded.
#'
#' @param ecosystem Character value of ecosystem, any listed on OSV database.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#'
#' @export
download_osv <- function(ecosystem = 'PyPI', refresh = FALSE) {

  ecosystem <- check_ecosystem(ecosystem)

  # Specific database URLs
  vul_url <- file.path('https://osv-vulnerabilities.storage.googleapis.com', ecosystem, 'all.zip')

  # Cache setup, only DL zip if not done today or in live session
  time_stamp <- Sys.time()
  date_stamp_hash <- digest::digest(as.Date(time_stamp))
  osv_cache <- file.path(tempdir(), paste0(ecosystem, '-', date_stamp_hash, '.zip'))

  if(!file.exists(osv_cache) || refresh) {
    message('Downloading from OSV online database...')
    utils::download.file(url = vul_url, destfile = osv_cache)
  }

  # Unzip for use...
  dl_dir <- file.path(tempdir(), paste0(ecosystem,'-unzipped-',date_stamp_hash))
  utils::unzip(osv_cache, exdir = dl_dir)

  return(list('osv_cache' = osv_cache,
              'dl_dir' = dl_dir))
}

#' Check input against possible ecosystems available
check_ecosystem <- function(ecosystem, suppressMessages = TRUE) {

  ecosystems <- tryCatch({
    fetch_ecosystems(offline = FALSE)
  },
  error = function(e) {
    if(!suppressMessages) message('Using offline version of ecosystem list...')
    fetch_ecosystems(offline = TRUE, refresh = refresh)
  })

  ecosystem <- match.arg(ecosystem, ecosystems$ecosystem, several.ok = FALSE)
  ecosystem
}

#' Fetch all available ecosystems
#'
#' @param offline Boolean, determine if use list bundled with package.
#' @param refresh Boolean, force refresh of cache when using online list.
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


#' Query OSV API for individual package vulnerabilities
#'
#' @param name Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param commit Commit hash to query against (do not use when version set).
#' @param purl URL for package (do not use if name or ecosystem set).
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param ... Additional parameters, for future development.
#'
#' @returns A list containing API query contents.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @export
osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, ...) {

  query_1 <- RosvQuery1()$run(commit,
                              version,
                              name,
                              ecosystem,
                              purl,
                              page_token)

  query_1$content
}

#' Query OSV API for vulnerabilities given a vector of packages
#'
#' Each query needs to be constructed from the provided set of vectors. Default
#' will be \code{NA} and thereby empty/null in the JSON request. If some values in the vector
#' are missing, use NA For large queries, the conversion to a formatted JSON
#' request can be parallelized via {future}.
#'
#' This returns the vulnerability ID and modified fields only, as per API instruction.
#'
#' @param packages Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param body_only Boolean value to return entire response or just the body content.
#' @param ... Additional parameters, for future development.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @export
osv_querybatch <- function(packages = NA, version = NA, ecosystem = NA, page_token = NA, body_only = TRUE, ...) {

  if(ecosystem == 'PyPI') packages <- normalize_pypi_pkg(packages)

  # Loop through to create each set
  batch_query <- furrr::future_pmap(list(packages, version, ecosystem, page_token),
                                    function(packages, version, ecosystem, page_token) {
                                      list(commit = NA,
                                           version = version,
                                           package = list(name = packages, ecosystem = ecosystem, purl = NA),
                                           page_token = page_token)
                                    })

  constructed_query <- list(queries = batch_query)

  req <- httr2::request('https://api.osv.dev/v1/querybatch')
  req <- httr2::req_headers(req, Accept = "application/json")
  req <- httr2::req_user_agent(req, '{{rosv}} (https://github.com/al-obrien/rosv)')
  req <- httr2::req_body_json(req, constructed_query)
  req <- httr2::req_retry(req, 3, backoff = ~10)

  resp <- httr2::req_perform(req)

  if(body_only) {
    httr2::resp_body_json(resp)
  } else {
    resp
  }
}

#' Query OSV API for vulnerabilities based on ID
#'
#' @param vuln_ids Vector of vulnerability IDs.
#'
#' Is usually paired with the batch outputs to grab more specific information.
#' @export
osv_vulns <- function(vuln_ids) {

  query_vulns <- RosvQueryVulns()$run(vuln_ids)

  query_vulns
}


#' Query OSV API for individual package vulnerabilities
#'
#' Will connect to OSV API and query vulnerabilities from the specified packages.
#' Unlike the other query functions, \code{osv_query} will only return content and not
#' the response object. All vulnerabilities are returned for any versions of the package flagged
#' in OSV.
#'
#' @details
#' Since the 'query' and 'batchquery' API endpoints have different outputs, this
#' function will align their contents to be a list of vulnerabilities. For 'query' this
#' meant flattening once, and for 'batchquery' it meant using IDs to fetch the additional
#' vulnerability information and then flattening the list.
#'
#' @param packages Name of package.
#' @param ecosystem Ecosystem package lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param ... Any other parameters to pass to nested functions, currently not used.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @examples
#' \dontrun{
#' # Single package
#' pkg_vul <- osv_query('dask', ecosystem = 'PyPI')
#'
#' # Batch query
#' pkg_vul <- osv_query(c('dask', 'dash'), ecosystem = 'PyPI')
#' }
#' @export
osv_query <- function(packages = NA, ecosystem = NA, page_token = NA,...) {

  if(length(packages) > 1) {
    batch_vulns <- osv_querybatch(packages = packages,
                                  version = NA,
                                  ecosystem = ecosystem,
                                  page_token = page_token,
                                  body_only = TRUE,
                                  ...)

    # Grab IDs for all Vulns and return the more details vulns info
    osv_vulns(unlist(purrr::map_depth(batch_vulns, 4, 'id'), use.names = FALSE), body_only = TRUE)

  } else {
    # Align by pre-plucking the vulnerability label
    purrr::pluck(osv_query_1(packages = packages,
                             version = NA,
                             ecosystem = ecosystem,
                             page_token = page_token,
                             body_only = TRUE,
                             ...), 1)
  }
}
