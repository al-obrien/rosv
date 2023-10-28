#' Download helper for OSV data
#'
#' Helper function to assist in downloading vulnerabilities information from OSV database.
#'
#' Any ecosystems listed \href{here}{'https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt'} can be downloaded.
#'
#' @param ecosystem Character value of ecosystem, any listed on OSV database.
#' @param id Vulnerability ID, default set to NULL to download all for provided ecosystem.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#'
#' @returns A list containing the cache and download locations for the vulnerability files.
#'
#' @examples
#' osv_dl <- download_osv('CRAN')
#'
#' # Clean up
#' try(unlink(osv_dl$osv_cache, recursive = TRUE))
#' try(unlink(osv_dl$dl_dir, recursive = TRUE))
#'
#' @export
download_osv <- function(ecosystem = 'PyPI', id = NULL, refresh = FALSE) {

  ecosystem <- check_ecosystem(ecosystem)
  time_stamp <- Sys.time()
  date_stamp_hash <- digest::digest(as.Date(time_stamp))

  # If providing specific ID
  if(!is.null(id)) {
    vul_url <- file.path('https://osv-vulnerabilities.storage.googleapis.com', ecosystem, paste0(id, '.json'))
    osv_cache_dir <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), paste0(ecosystem, '-', date_stamp_hash))
    osv_cache_file <- file.path(osv_cache_dir, paste0(id, '.json'))
    if(!dir.exists(osv_cache_dir)) dir.create(osv_cache_dir)

    if(!file.exists(osv_cache_file) || refresh) {
      message('Downloading from OSV online database...')
      utils::download.file(url = vul_url, destfile = osv_cache_file)
    }

    return(list('osv_cache' = osv_cache_file,
                'dl_dir' = osv_cache_dir))

  # If downloading all JSON for ecosystem
  } else {
    vul_url <- file.path('https://osv-vulnerabilities.storage.googleapis.com', ecosystem, 'all.zip')

    # Cache setup, only DL zip if not done today or in live session
    osv_cache <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), paste0(ecosystem, '-', date_stamp_hash, '-', 'all.zip'))

    if(!file.exists(osv_cache) || refresh) {
      message('Downloading from OSV online database...')
      utils::download.file(url = vul_url, destfile = osv_cache)
    }

    # Unzip for use...
    dl_dir <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), paste0(ecosystem,'-unzipped-',date_stamp_hash))
    utils::unzip(osv_cache, exdir = dl_dir)

    return(list('osv_cache' = osv_cache,
                'dl_dir' = dl_dir))

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
#'
#' @examples
#' osv_query_1(commit = '6879efc2c1596d11a6a6ad296f80063b558d5e0f')
#'
#'
#' @export
osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, ...) {

  query_1 <- RosvQuery1$new(commit,
                            version,
                            name,
                            ecosystem,
                            purl,
                            page_token)
  query_1$run()

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
#' @param name Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param commit Commit hash to query against (do not use when version set).
#' @param purl URL for package (do not use if name or ecosystem set).
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param ... Additional parameters, for future development.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#' @export
osv_querybatch <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, ...) {

  querybatch <- RosvQueryBatch$new(commit,
                                   version,
                                   name,
                                   ecosystem,
                                   purl,
                                   page_token)

  querybatch$run()

  # Parse the content field, if user needs raw lists, still available to extract in resp field.
  querybatch$parse()

  querybatch
}

#' Query OSV API for vulnerabilities based on ID
#'
#' @param vuln_ids Vector of vulnerability IDs.
#'
#' Is usually paired with the batch outputs to grab more specific information.
#' @export
osv_vulns <- function(vuln_ids) {

  vulns <- RosvVulns$new(vuln_ids)
  vulns$run()

  vulns$content
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
#' @param name Name of package(s).
#' @param ecosystem Ecosystem(s) package(s) lives within.
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
#' name_vec <- c('dask', 'dash')
#' ecosystem_vec <- rep('PyPI', length(name_vec))
#' pkg_vul <- osv_query(name_vec, ecosystem = ecosystem_vec)
#' }
#' @export
osv_query <- function(name = NULL, ecosystem = NULL, page_token = NULL, ...) {

  if(length(name) > 1) {
    batch_vulns <- osv_querybatch(name = name,
                                  ecosystem = ecosystem,
                                  page_token = page_token,
                                  ...)

    # Grab IDs for all Vulns and return the more details vulns info
    osv_vulns(unlist(purrr::map_depth(batch_vulns, 4, 'id'), use.names = FALSE))

  } else {
    # Align by pre-plucking the vulnerability label
    purrr::pluck(osv_query_1(name = name,
                             ecosystem = ecosystem,
                             ...), 1)
  }
}
