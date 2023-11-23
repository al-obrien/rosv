#' R6 Class for OSV Query Endpoint
#'
#' @description
#' An R6 class to provide a lower-level interface to the query endpoint of the OSV API.
#'
#' @details
#' Pageination is implemented via \code{httr2::req_perform_iterative()} and a private method for
#' extracting tokens automatically. When initialized, the page_token is set to \code{NULL};
#' if a token is generated for large results the process is handled internally. The response object
#' will contain a list of all returned responses before any formatting occurred. The content field will
#' contain the list of vulnerabilities which may be further parsed into a table format.
#'
#' @param commit Commit hash to query against (do not use when version set).
#' @param version Version of package.
#' @param name Name of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param purl URL for package (do not use if \code{name} or \code{ecosystem} is set).
#'
#' @returns An R6 object to operate with OSV query endpoint.
#'
#' @seealso \url{https://google.github.io/osv.dev/post-v1-query/}
#'
#' @examples
#' query <- RosvQuery1$new(commit = '6879efc2c1596d11a6a6ad296f80063b558d5e0f')
#' query
#' @export
RosvQuery1 <- R6::R6Class('RosvQuery1',
                          public = list(

                            #' @field request Request object made by \code{httr2}.
                            request = NULL,

                            #' @field content Body contents of response from OSV API.
                            content = NULL,

                            #' @field response Response object returned from OSV API.
                            response = NULL,

                            #' @description
                            #' Set the core request details for subsequent use when called in \code{run()} method.
                            initialize = function(commit = NULL,
                                                  version = NULL,
                                                  name = NULL,
                                                  ecosystem = NULL,
                                                  purl = NULL) {

                              # Checks on input lengths (NULLs are 0), specific to osv_query_1
                              if(length(commit) > 1) stop('Only provide one commit.')
                              if(length(version) > 1 | length(name) > 1) stop('Only one package and version can be provided.')
                              if(length(ecosystem) > 1) stop('Length of ecosystem vector must be 1.')
                              if(length(purl) > 1) stop('Length of package URL must be 1.')

                              # Perform general rule checks for queries (single or batch)
                              private$validate_query(commit, version, name, ecosystem, purl)

                              # Parse inputs for use specific to this endpoint
                              constructed_query <- list(commit = commit,
                                                        version = version,
                                                        package = list(name = name, ecosystem = ecosystem, purl = purl),
                                                        page_token = NULL)

                              # Perform request, get response
                              req <- private$core_query('query')
                              req <- httr2::req_body_json(req, constructed_query)

                              self$request <- req
                            },

                            #' @description
                            #' Perform the request and return response for OSV API call.
                            run = function() {

                              resp <- httr2::req_perform_iterative(self$request, next_req = private$iterate_osv_page)

                              # Assign to main variables (just vulns, not tokens)
                              self$content <- list(vulns = httr2::resps_data(resp, function(x) httr2::resp_body_json(x)$vulns))

                              self$response <- resp
                              # invisible(self) # If want to be able to chain content at confusion of reference semantics

                            },

                            #' @description
                            #' Parse the contents returned into a tidier format. Can
                            #' use \code{future} plans to help parallelize. Not all contents are parsed.
                            parse = function() {
                              stopifnot(!is.null(self$content))

                              if(length(self$content) == 1 & (!is.null(names(self$content)) && names(self$content) == 'vulns')) {
                                self$content <- purrr::pluck(self$content, 'vulns')
                              }

                              # Extract all nested details of interests for versions of packages under affected array
                              affected_versions <- furrr::future_map(self$content,
                                                                     ~purrr::map(purrr::pluck(., 'affected'), private$extract_details))


                              # Collapse within each pkg set (e.g. tensorflow can have several affected per vulns)
                              affected_versions <- purrr::map(affected_versions, purrr::list_rbind)

                              # Combine summary details per vulns with nested affected details and collapse into 1 dataframe
                              self$content <- purrr::list_rbind(
                                purrr::map2(purrr::map(self$content, private$extract_summary),
                                            affected_versions,
                                            function(x,y) cbind(data.frame(x), y)))
                              # invisible(self) # If want to be able to chain content at confusion of reference semantics


                            },

                            #' @description
                            #' Print basic details of query object to screen.
                            #' @param ... Reserved for possible future use.
                            print = function(...) {
                              if(!is.null(self$response)) {
                                success_length <- length(httr2::resps_successes(self$response))
                                cat('Request made to:', self$request$url , '\n')
                                cat('Successful responses of total:', success_length, '/', length(self$response), '\n')
                                cat('Successful content size (bytes):',
                                    sum(as.double(vapply(httr2::resps_successes(self$response), function(x) purrr::pluck(httr2::resp_headers(x), 'Content-Length'), character(success_length)))),
                                    '\n')
                              } else {
                                cat('Request made to:', NA , '\n')
                                cat('Successful responses of total:', NA, '\n')
                                cat('Successful content size (bytes):', NA, '\n')
                              }
                              invisible(self)
                            }
                          ),

                          private = list(

                            # @description
                            # Create the core query to use across specific endpoints.
                            # @param endpoint Character value for name of endpoint in OSV API.
                            core_query = function(endpoint) {

                              req <- httr2::request('https://api.osv.dev/v1')
                              req <- httr2::req_url_path_append(req, endpoint)
                              req <- httr2::req_user_agent(req, '{{rosv}} (https://github.com/al-obrien/rosv)')
                              req <- httr2::req_headers(req, Accept = "application/json")
                              req <- httr2::req_retry(req, 3, backoff = ~10)
                              req

                            },

                            # Helper function to check for NULLS and replace with NA in lists
                            modify_helper = function(input) {
                              purrr::modify_if(input, is.null,
                                               function(x) NA_character_,
                                               .else = function(x) x)
                            },

                            # Extract summary info into a list for subsequent combination with nested
                            extract_summary = function(x) {
                              summary_list <- list(id = purrr::pluck(x, 'id'),
                                                   summary = purrr::pluck(x, 'summary'),
                                                   modified = purrr::pluck(x, 'modified'),
                                                   published = purrr::pluck(x, 'published'))
                              private$modify_helper(summary_list)
                            },

                            # Extract package and version details and append into a data.frame all at once for lowest levels
                            # Specific for query1 or vulns extractions
                            extract_details = function(x) {

                              # Pkg details
                              pkg_details <- purrr::pluck(x, 'package')

                              # Versions unlisted
                              versions <- unlist(purrr::pluck(x, 'versions'))

                              # Combine list with reformatted list and make a dataframe
                              data.frame(
                                private$modify_helper(append(pkg_details, list(versions = versions)))
                              )
                            },

                            # Iterator for OSV pagination tokens for single queries
                            iterate_osv_page = function(resp, req) {

                              json_body <- httr2::resp_body_json(resp)
                              tokens <- json_body$next_page_token

                              # Break out if all tokens are NULL
                              if(is.null(tokens)) return(NULL)

                              # Modify new request with new tokens
                              httr2::req_body_json_modify(req, page_token = tokens)

                            },

                            validate_query = function(commit, version, name, ecosystem, purl) {

                              # Valid ecosystem selection
                              if(!is.null(ecosystem)) {
                                ecosystem <- check_ecosystem(ecosystem)
                                if(any(ecosystem == 'PyPI') & !is.null(name)) name[ecosystem == 'PyPI'] <- normalize_pypi_pkg(name[ecosystem == 'PyPI'])
                              }

                              # Invalid combinations (as defined in API)
                              if(!is.null(commit) & !is.null(version)) stop('Cannot provide commit hash and version at the same time.')
                              if(!is.null(purl) & (!is.null(name) | !is.null(ecosystem))) stop('Cannot provide purl with name or ecosystem also set.')
                              if(!is.null(name) & is.null(ecosystem)) stop('If using package name, ecosystem must also be set')

                              # Enforce stricter limits to simplify batch and mental model (vectors that can occur together should be same length or not provided)
                              if(!is.null(commit) & (!is.null(name) | !is.null(purl))) stop('Separate commit hash queries from package based queries.')
                              if(length(name) != length(ecosystem)) stop('Package name and ecosystem must be same length for vectorized operations.')
                              if(!is.null(version) & !is.null(name)) {
                                if(length(version) != length(ecosystem)) stop('Package name and versions must be same length for vectorized operations.')
                              }
                            }
                          )
)



