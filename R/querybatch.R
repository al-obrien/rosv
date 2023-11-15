#' Query OSV API for vulnerabilities given a vector of packages
#'
#' Using a vector of input information, query the OSV API for any associated
#' vulnerability ID.
#'
#' @details
#' The query is constructed from the provided set of vectors. Default
#' will be \code{NULL} and thereby empty/null in the JSON request. If some values in the vector
#' are missing, use \code{NA}. For many queries, the conversion to a formatted JSON
#' request can be parallelized via \{future\}.
#'
#' The returned information are vulnerability IDs and modified fields only, as per API instruction.
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
osv_querybatch <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, parse = TRUE, cache = TRUE, ...) {
  if(cache) {
    .osv_querybatch_cache(commit = commit,
                          version = version,
                          name = name,
                          ecosystem = ecosystem,
                          purl = purl,
                          parse = parse,
                          ...)
  } else {
    .osv_querybatch(commit = commit,
                    version = version,
                    name = name,
                    ecosystem = ecosystem,
                    purl = purl,
                    parse = parse,
                    ...)
  }
}

#' @describeIn osv_querybatch Internal function to run \code{osv_querybatch} without caching.
.osv_querybatch <- function(name = NULL, version = NULL, ecosystem = NULL, commit = NULL, purl = NULL, parse = TRUE, cache = TRUE, ...) {

  querybatch <- RosvQueryBatch$new(commit,
                                   version,
                                   name,
                                   ecosystem,
                                   purl,
                                   ...)

  querybatch$run()

  # Parse the content field, if user needs raw lists, still available to extract in resp field.
  if(parse) querybatch$parse()

  querybatch
}

#' @describeIn osv_querybatch Internal function to run a memoise and cached version of \code{osv_querybatch}.
.osv_querybatch_cache <- function() {
  # Placeholder for documentation
}
