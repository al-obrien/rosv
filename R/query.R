#' Download helper for OSV data
#'
#' Helper function to assist in downloading vulnerabilities information from OSV database.
#'
#' Any ecosystems listed \href{https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt}{here} can be downloaded.
#'
#' @param ecosystem Character value of ecosystem, any listed on OSV database.
#' @param id Vulnerability ID, default set to NULL to download all for provided ecosystem.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#'
#' @returns A list containing the cache and download locations for the vulnerability files.
#'
#' @examplesIf interactive()
#'
#' osv_dl <- download_osv('CRAN')
#'
#' # Clean up
#' try(unlink(osv_dl$osv_cache, recursive = TRUE))
#' try(unlink(osv_dl$dl_dir, recursive = TRUE))
#'
#' @export
download_osv <- function(ecosystem, id = NULL, refresh = FALSE) {

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
#' Will connect to OSV API and query vulnerabilities from the specified packages.
#' Unlike the other query functions, \code{osv_query} will only return content and not
#' the response object. By default all vulnerabilities are returned for any versions of the package flagged
#' in OSV. This can be subset manually or via the parameter \code{all_affected}.
#'
#' @details
#' Since the 'query' and 'batchquery' API endpoints have different outputs, this
#' function will align their contents to be a list of vulnerabilities. For 'query' this
#' meant flattening once, and for 'batchquery' it meant using IDs to fetch the additional
#' vulnerability information and then flattening the list.
#'
#' Since the OSV database is organized by vulnerability, the returned content may have duplicate
#' package details as the same package and possibly its version may occur within several different
#' reported vulnerabilities.
#'
#' Due to variations in formatting from the OSV API, not all responses have versions associated in
#' the response but instead use ranges. Filtering currently does not apply to this field and may return
#' all versions affected within the ranges. If you suspect ranges are used instead of specific version codes,
#' examine the response object using lower-level functions like \code{osv_query1()}.
#'
#' @param name Character vector of package names..
#' @param version Character vector of package versions, \code{NA} if ignoring versions.
#' @param ecosystem Character vector of ecosystem(s) within which the package(s) exist.
#' @param page_token For large result sizes, the next response to complete set requires a page_token (for future use).
#' @param all_affected Boolean value, if \code{TRUE} will return all package results found per vulnerability discovered.
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
osv_query <- function(name = NULL, version = NULL, ecosystem = NULL, page_token = NULL, all_affected = TRUE, cache = TRUE, ...) {

  if(length(name) > 1) {
    batch_vulns <- get_content(osv_querybatch(name = name,
                                              version = version,
                                              ecosystem = ecosystem,
                                              page_token = page_token,
                                              cache = cache,
                                              ...))

    # Grab IDs for all Vulns and return the more details vulns info
    batch_vulns <- get_content(osv_vulns(batch_vulns$id, cache = cache))


    if(!all_affected) {
      batch_vulns <- filter_affected(batch_vulns, name, ecosystem, version)
    }

    structure(batch_vulns, class = c('rosv_query', 'data.frame'))

  } else {
    # Align by pre-plucking the vulnerability label
    query1 <- get_content(osv_query_1(name = name,
                                      version = version,
                                      ecosystem = ecosystem,
                                      cache = cache,
                                      ...))

    if(!all_affected) {
      query1 <- filter_affected(query1, name, ecosystem, version)
    }

    structure(query1,
              class = c('rosv_query', 'data.frame'))
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
#' @returns A named vector of logical values.
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

  results_vec[as.integer(index$result)] <- TRUE
  names(results_vec) <- name
  results_vec

}

