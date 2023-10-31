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
#' @examplesIf interactive()
#'
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
#' @param parse Boolean value to set if the content field should be parsed from JSON list format.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#' @param ... Additional parameters passed to nested functions.
#'
#' @returns An R6 object containing API query contents.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#'
#' @examples
#' osv_query_1(commit = '6879efc2c1596d11a6a6ad296f80063b558d5e0f')
#'
#' @export
osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, parse = TRUE, cache = TRUE, ...) {

  if(cache) {
    .osv_query_1_cache(commit = commit,
                       version = version,
                       name = name,
                       ecosystem = ecosystem,
                       purl = purl,
                       page_token = page_token,
                       parse = parse,
                       ...)
  } else {
    .osv_query_1(commit = commit,
                 version = version,
                 name = name,
                 ecosystem = ecosystem,
                 purl = purl,
                 page_token = page_token,
                 parse = parse,
                 ...)
  }
}


#' @describeIn osv_query_1 Internal function to run osv_query_1 without caching
.osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, parse = TRUE, cache = TRUE, ...) {

  query_1 <- RosvQuery1$new(commit,
                            version,
                            name,
                            ecosystem,
                            purl,
                            page_token,
                            ...)
  query_1$run()
  if(parse) query_1$parse()

  query_1
}

#' @describeIn osv_query_1 Internal function to run a memoise and cached version of osv_query_1
#' @importFrom memoise memoise
.osv_query_1_cache <- function() {
  # Placeholder for documentation
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
#' @inheritParams osv_query_1
#'
#' @returns An R6 object containing API query contents.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#'
#' @examplesIf interactive()
#' osv_querybatch(c("commonmark", "dask"), ecosystem = c('CRAN', 'PyPI'))
#'
#' @export
osv_querybatch <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, parse = TRUE, cache = TRUE, ...) {
  if(cache) {
    .osv_querybatch_cache(commit = commit,
                          version = version,
                          name = name,
                          ecosystem = ecosystem,
                          purl = purl,
                          page_token = page_token,
                          parse = parse,
                          ...)
  } else {
    .osv_querybatch(commit = commit,
                    version = version,
                    name = name,
                    ecosystem = ecosystem,
                    purl = purl,
                    page_token = page_token,
                    parse = parse,
                    ...)
  }
}

#' @describeIn osv_querybatch Internal function to run osv_querybatch without caching
.osv_querybatch <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, page_token = NA, parse = TRUE, cache = TRUE, ...) {

  querybatch <- RosvQueryBatch$new(commit,
                                   version,
                                   name,
                                   ecosystem,
                                   purl,
                                   page_token,
                                   ...)

  querybatch$run()

  # Parse the content field, if user needs raw lists, still available to extract in resp field.
  if(parse) querybatch$parse()

  querybatch
}

#' @describeIn osv_querybatch Internal function to run a memoise and cached version of osv_querybatch
.osv_querybatch_cache <- function() {
 # Placeholder for documentation
}

#' Query OSV API for vulnerabilities based on ID
#'
#' Use vulnerability IDs to extract more details information. Usually is paired with \code{osv_querybatch}.
#'
#' @param vuln_ids Vector of vulnerability IDs.
#' @param parse Boolean value to set if the content field should be parsed from JSON list format.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#'
#' @returns An R6 object containing API query contents.
#'
#' @examplesIf interactive()
#' vulns <- osv_vulns("RSEC-2023-8")
#' get_content(vulns)
#'
#' @export
osv_vulns <- function(vuln_ids, parse = TRUE, cache = TRUE) {

  if(cache) {
    .osv_vulns_cache(vuln_ids = vuln_ids,
                     parse = parse)
  } else {
    .osv_vulns(vuln_ids = vuln_ids,
               parse = parse)
  }
}

#' @describeIn osv_vulns Internal function to run osv_vulns without caching
.osv_vulns <- function(vuln_ids, parse = TRUE) {

  vulns <- RosvVulns$new(vuln_ids)
  vulns$run()
  if(parse) vulns$parse()

  vulns
}


#' @describeIn osv_vulns Internal function to run a memoise and cached version of osv_vulns
.osv_vulns_cache <- function(vuln_ids, parse = TRUE) {
  # Placeholder for documentation
}

#' Query OSV API for individual package vulnerabilities
#'
#' Will connect to OSV API and query vulnerabilities from the specified packages.
#' Unlike the other query functions, \code{osv_query} will only return content and not
#' the response object. By default all vulnerabilities are returned for any versions of the package flagged
#' in OSV. This can be subset manually or via the parameter \code{all_affected_versions}.
#'
#' @details
#' Since the 'query' and 'batchquery' API endpoints have different outputs, this
#' function will align their contents to be a list of vulnerabilities. For 'query' this
#' meant flattening once, and for 'batchquery' it meant using IDs to fetch the additional
#' vulnerability information and then flattening the list.
#'
#' @param name Name of package(s).
#' @param version Version of package.
#' @param ecosystem Ecosystem(s) package(s) lives within.
#' @param page_token When large number of results, next response to complete set requires a page_token.
#' @param all_affected_versions Boolean value, if \code{TRUE} will return all versions found per vulnerability discovered.
#' @param ... Any other parameters to pass to nested functions.
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
osv_query <- function(name = NULL, version = NULL, ecosystem = NULL, page_token = NULL, all_affected_versions = TRUE, ...) {

  if(length(name) > 1) {
    batch_vulns <- get_content(osv_querybatch(name = name,
                                              version = version,
                                              ecosystem = ecosystem,
                                              page_token = page_token,
                                              ...))

    batch_vulns <- get_content(osv_vulns(batch_vulns$id))

    # Grab IDs for all Vulns and return the more details vulns info

    if(!all_affected_versions) {
      stopifnot(all(!is.na(version))) # Must specify all versions to subset properly
      batch_vulns <- subset(batch_vulns,
                            (batch_vulns$versions == version & batch_vulns$name == name & batch_vulns$ecosystem == ecosystem) | is.na(batch_vulns$versions))
    }

    structure(batch_vulns, class = c('rosv_query', 'data.frame'))

  } else {
    # Align by pre-plucking the vulnerability label
    query1 <- get_content(osv_query_1(name = name,
                                      version = version,
                                      ecosystem = ecosystem,
                                      ...))

    if(!all_affected_versions) {
      stopifnot(all(!is.na(version))) # Must specify all versions to subset properly
      query1 <- subset(query1,
                       (query1$versions == version & query1$name == name & query1$ecosystem == ecosystem) | is.na(query1$versions))
    }

    structure(query1,
              class = c('rosv_query', 'data.frame'))
  }
}

#' Detect if package within ecosystem has reported vulnerabilities
#'
#' Search the OSV database, by package name and its respective ecosystem, to determine
#' if a vulnerability has ever been listed. If a package has been listed as impacted by
#' a vulnerability, this may warrant further queries to investigate specific versions
#' that have been affected.
#'
#' @inheritParams osv_query
#' @returns A named vector of logical values.
#'
#' @examplesIf interactive()
#' is_pkg_vulnerable(c('dask', 'dplyr'), c('PyPI', 'CRAN'))
#'
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

