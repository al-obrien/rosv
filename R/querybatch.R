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
