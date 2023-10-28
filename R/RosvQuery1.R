#' R6 Class for OSV Query Endpoint
#'
#' @description
#' An R6 class to provide a lower-level interface to the query endpoint of the OSV API.
#'
#' @details
#' Pageination not implemented yet, waiting for httr2 updates to add, then will handle automatically
#'
#' @param commit Commit hash to query against (do not use when version set).
#' @param version Version of package.
#' @param name Name of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param purl URL for package (do not use if name or ecosystem set).
#' @param page_token When large number of results, next response to complete set requires a page_token.
#'
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
                                                  purl = NULL,
                                                  page_token = NULL) {

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
                                                        page_token = page_token)

                              # Perform request, get response
                              req <- private$core_query('query')
                              req <- httr2::req_body_json(req, constructed_query)

                              self$request <- req
                            },

                            #' @description
                            #' Perform the request and return response for OSV API call.
                            run = function() {

                              resp <- httr2::req_perform(self$request)

                              # Assign to main variables
                              self$content <- httr2::resp_body_json(resp)
                              self$response <- resp

                            },

                            #' @description
                            #' Parse the contents returned into a tidier format.
                            parse = function() {
                              stopifnot(!is.null(self$content))

                            },

                            #' @description
                            #' Print basic details of query object to screen.
                            #' @param ... Reserved for possible future use.
                            print = function(...) {
                              if(!is.null(self$response)) {
                                cat('Request made to:', self$request$url , '\n')
                                cat('Response status of:', self$response$status_code, httr2::resp_status_desc(self$response), '\n')
                                cat('Content length is:', httr2::resp_headers(self$response)$`Content-Length`, '\n')
                              } else {
                                cat('Request made to:', NA , '\n')
                                cat('Response status of:', NA, '\n')
                                cat('Content length is:', NA, '\n')
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


