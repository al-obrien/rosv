#' Query OSV API for vulnerabilities based upon an individual package
#'
#' Query the OSV API for vulnerabilities that include the individual package of interest.
#' The request is automatically constructed from the provided elements and the returned
#' values are parsed into a \code{data.frame}.
#'
#' @param name Name of package.
#' @param version Version of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param commit Commit hash to query against (do not use when version set).
#' @param purl URL for package (do not use if name or ecosystem set).
#' @param parse Boolean value to set if the content field should be parsed from JSON list format.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#' @param ... Additional parameters passed to nested functions.
#'
#' @returns An R6 object containing API query contents.
#'
#' @seealso \href{https://ossf.github.io/osv-schema/#affectedpackage-field}{Ecosystem list}
#'
#' @examplesIf interactive()
#' osv_query_1(commit = '6879efc2c1596d11a6a6ad296f80063b558d5e0f')
#'
#' @export
osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, parse = TRUE, cache = TRUE, ...) {

  if(cache) {
    .osv_query_1_cache(commit = commit,
                       version = version,
                       name = name,
                       ecosystem = ecosystem,
                       purl = purl,
                       parse = parse,
                       ...)
  } else {
    .osv_query_1(commit = commit,
                 version = version,
                 name = name,
                 ecosystem = ecosystem,
                 purl = purl,
                 parse = parse,
                 ...)
  }
}


#' @describeIn osv_query_1 Internal function to run \code{osv_query_1} without caching.
.osv_query_1 <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, parse = TRUE, cache = TRUE, ...) {

  query_1 <- RosvQuery1$new(commit,
                            version,
                            name,
                            ecosystem,
                            purl,
                            ...)
  query_1$run()
  if(parse) query_1$parse()

  query_1
}

#' @describeIn osv_query_1 Internal function to run a memoise and cached version of \code{osv_query_1}.
#' @importFrom memoise memoise
.osv_query_1_cache <- function() {
  # Placeholder for documentation
}
