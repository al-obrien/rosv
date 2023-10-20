#' Download helper for OSV data
#'
#' Helper function to assist in downloading vulnerabilities information from OSV database.
#'
#' @param type Character value of either 'pypi' or 'cran'.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
download_osv <- function(type = 'pypi', refresh = FALSE) {

  # Specific database URLs
  vul_url <- if(type == 'pypi') {
    'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip'
  } else if (type == 'cran') {
    'https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip'
  }

  # Cache setup, only DL zip if not done today or in live session
  time_stamp <- Sys.time()
  date_stamp_hash <- digest::digest(as.Date(time_stamp))
  osv_cache <- file.path(tempdir(), paste0(type, '-', date_stamp_hash, '.zip'))

  if(!file.exists(osv_cache) || refresh) {
    message('Downloading from OSV online database...')
    download.file(url = vul_url, destfile = osv_cache)
  }

  # Unzip for use...
  dl_dir <- file.path(tempdir(), paste0(type,'-unzipped-',date_stamp_hash))
  unzip(osv_cache, exdir = dl_dir)

  return(list('osv_cache' = osv_cache,
              'dl_dir' = dl_dir))
}

#' Query OSV API for individual package vulnerabilities
#'
#' @param packages Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param body_only Boolean value to return entire response or just the body content.
#' @param ... Additional parameters, for future development.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
osv_query_1 <- function(packages = NA, version = NA, ecosystem = NA, page_token = NA, body_only = TRUE, ...) {
  constructed_query <- list(commit = NA,
                            version = version,
                            package = list(name = packages, ecosystem = ecosystem, purl = NA),
                            page_token = page_token)

  req <- httr2::request('https://api.osv.dev/v1/query')
  req <- httr2::req_headers(req, Accept = "application/json")
  req <- httr2::req_body_json(req, constructed_query)
  req <- httr2::req_retry(req, 3, backoff = ~10)

  resp <- httr2::req_perform(req)

  if(body_only) {
    httr2::resp_body_json(resp)
  } else {
    resp
  }
}

#' Query OSV API for vulnerabilities given a vector of packages
#'
#' Each query needs to be constructed from the provided set of vectors. Default
#' will be \code{NA} and thereby empty/null in the JSON request. If some values in the vector
#' are missing, use NA For large queries, the conversion to a formatted JSON
#' request can be parallelized via {future}.
#'
#' @param packages Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param body_only Boolean value to return entire response or just the body content.
#' @param ... Additional parameters, for future development.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
osv_querybatch <- function(packages = NA, version = NA, ecosystem = NA, page_token = NA, body_only = TRUE, ...) {
browser()
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
  req <- httr2::req_body_json(req, constructed_query)
  req <- httr2::req_retry(req, 3, backoff = ~10)

  resp <- httr2::req_perform(req)

  if(body_only) {
    httr2::resp_body_json(resp)
  } else {
    resp
  }
}

#' Query OSV API for individual package vulnerabilities
#'
#' Will connect to OSV API and query vulnerabilities from the specified packages.
#'
#' @param packages Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param body_only Boolean value to return entire response or just the body content.
#' @param ... Any other parameters to pass to nested functions, currently not used.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @examples
#' \dontrun{
#' pkg_vul <- osv_query('dask', ecosystem = 'PyPI')
#' extract_vul_info(pkg_vul)
#'
#' # Batch query
#' pkg_vul <- osv_query(c('dask', 'dash'), ecosystem = 'PyPI')
#' extract_vul_info(pkg_vul)
#' }
#' @export
osv_query <- function(packages = NA, version = NA, ecosystem = NA, page_token = NA, body_only = TRUE,...) {

  if(length(packages) > 1) {
    osv_querybatch(packages = packages,
                   version = version,
                   ecosystem = ecosystem,
                   page_token = page_token,
                   body_only = body_only,
                   ...)
  } else {
    osv_query_1(packages = packages,
                version = version,
                ecosystem = ecosystem,
                page_token = page_token,
                body_only = body_only,
                ...)
  }
}
