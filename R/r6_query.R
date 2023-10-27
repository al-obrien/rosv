# Pageination not implemetned yet, waiting for httr2 updates to add, then will handle automatically
RosvQuery1 <- R6::R6Class('RosvQuery1',
                          public = list(
                            request = NULL,
                            content = NULL,
                            response = NULL,

                            # initialize = function() {
                            #
                            # },

                            run = function(commit = NULL,
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
                              req <- private$core_query()
                              req <- httr2::req_url_path_append(req, 'query')
                              req <- httr2::req_body_json(req, constructed_query)
                              resp <- httr2::req_perform(req)

                              # Assign to main variables
                              self$request <- req
                              self$content <- httr2::resp_body_json(resp)
                              self$response <- resp

                            },

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
                            core_query = function() {

                              req <- httr2::request('https://api.osv.dev/v1')
                              req <- httr2::req_user_agent(req, '{{rosv}} (https://github.com/al-obrien/rosv)')
                              req <- httr2::req_headers(req, Accept = "application/json")
                              req <- httr2::req_retry(req, 3, backoff = ~10)
                              req

                            },

                            validate_query = function(commit, version, name, ecosystem, purl) {

                              # Valid ecosystem selection
                              if(!is.null(ecosystem)) {
                                ecosystem <- check_ecosystem(ecosystem)
                                if(ecosystem == 'PyPI' & !is.null(name)) name <- normalize_pypi_pkg(name)
                              }

                              # Invalid combinations
                              if(!is.null(commit) & !is.null(version)) stop('Cannot provide commit hash and version at the same time.')
                              if(!is.null(purl) & (!is.null(name) | !is.null(ecosystem))) stop('Cannot provide purl with name or ecosystem also set.')
                              if(!is.null(name) & is.null(ecosystem)) stop('If using package name, ecosystem must also be set')

                              }
                            )
                          )


RosvQueryVulns <- R6::R6Class('RosvQueryVulns',
                              inherit = RosvQuery1,
                              public = list(

                                run = function(vuln_ids) {

                                  stopifnot(is.character(vuln_ids))

                                  # Perform request, get response
                                  req <- private$core_query()
                                  req <- httr2::req_url_path_append(req, 'vulns')

                                  reqs <- purrr::map(vuln_ids, function(x) httr2::req_url_path_append(req, x))
                                  resps <- purrr::map(reqs, httr2::req_perform)

                                  # Assign to main variables
                                  self$request <- reqs
                                  self$content <- purrr::map(resps, httr2::resp_body_json)
                                  self$response <- resps
                                },

                                print = function(...) {
                                  if(!is.null(self$response)) {
                                    cat('Requests made to "https://api.osv.dev/v1/vulns":', length(self$request) , '\n')
                                    cat('Responses with status of "200":', sum(purrr::map_dbl(self$response, function(x) purrr::pluck(x, 'status_code')) == 200), '\n')
                                  } else {
                                    cat('Request made to:', NA , '\n')
                                    cat('Response status of:', NA, '\n')
                                  }
                                  invisible(self)
                                }

                              ),
                              private = list(

                                validate_query = function() {
                                  NULL
                                }
                              ))
