#' R6 Class for OSV Querybatch Endpoint
#'
#' @description
#' An R6 class to provide a lower-level interface to the querybatch
#' endpoint of the OSV API. Batches are enforced to only process by commit hash, purl, or name+ecosystem.
#' This avoids some confusion as to which is taken preferentially and simplifies query creation.
#'
#' @details
#' Pageination is implemented via \code{httr2::req_perform_iterative()} and a private method for
#' extracting tokens automatically. When initialized, the page_token is set to \code{NULL};
#' if a token is generated for large results the process is handled internally. The response object
#' will contain a list of all returned responses before any formatting occurred. The content field will
#' contain the list of results with vulnerabilities which may be further parsed into a table format.
#'
#' @param commit Commit hash to query against (do not use when version set).
#' @param version Version of package.
#' @param name Name of package.
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param purl URL for package (do not use if \code{name} or \code{ecosystem} is set).
#'
#' @returns An R6 object to operate with OSV querybatch endpoint.
#'
#' @seealso \url{https://google.github.io/osv.dev/post-v1-querybatch/}
#'
#' @examples
#' pkgs <- c('jinja2', 'dask')
#' ecosystem <- rep('PyPI', length(pkgs))
#' batchquery <- RosvQueryBatch$new(name = pkgs, ecosystem = ecosystem)
#' batchquery
#'
#' @export
RosvQueryBatch <- R6::R6Class('RosvQueryBatch',
                              inherit = RosvQuery1,

                              public = list(

                                #' @description
                                #' Set the core request details for subsequent use when called in \code{run()} method.
                                initialize = function(commit = NULL,
                                                      version = NULL,
                                                      name = NULL,
                                                      ecosystem = NULL,
                                                      purl = NULL) {

                                  # Validate
                                  private$validate_query(commit, version, name, ecosystem, purl)

                                  # Identify nulls, drop where that exists, and allow nested function to carry through null values based upon named list
                                  not_null <- unlist(purrr::map(list(commit, version, name, ecosystem, purl), function(x) !is.null(x)))
                                  valid_input <- list(commit = commit, version = version, name = name, ecosystem = ecosystem, purl = purl)
                                  valid_input <- valid_input[not_null]

                                  # Loop through to create each set using template
                                  batch_query <- furrr::future_pmap(valid_input, private$create_batch_list)

                                  constructed_query <- list(queries = batch_query)

                                  # Perform request, get response
                                  req <- private$core_query('querybatch')
                                  req <- httr2::req_body_json(req, constructed_query)

                                  self$request <- req

                                },

                                #' @description
                                #' Perform the request and return response for OSV API call.
                                run = function() {

                                  resp <- httr2::req_perform_iterative(self$request, private$iterate_osv_page)

                                  # Assign to main variables
                                  self$content <- private$collapse_paged(httr2::resps_data(resp, function(x) httr2::resp_body_json(x)))
                                  self$response <- resp

                                },

                                #' @description
                                #' Parse the contents returned into a tidier format.
                                #'
                                #' @details
                                #' When no result is found, any empty list is returned by the API, which
                                #' during parsing will be dropped as the list is flattened. However, the
                                #' index of the list is still accessible and the dropped items can easily
                                #' be identified from the results column. Not all contents are parsed.
                                parse = function() {
                                  stopifnot(!is.null(self$content))

                                  # Check if only 1 result passed in for edge case handling
                                  rslt_n <- purrr::map_int(self$content, length)

                                  # Flatten content and pulls vulns out to get into results list and use number for naming
                                  flat_results_list <- purrr::map_depth(purrr::list_flatten(self$content, name_spec =  '{inner}'), 1, 'vulns')

                                  # Expand result name vector
                                  rslt_lengths <- purrr::map_int(flat_results_list, length)
                                  if(rslt_n > 1) rslt_names <- names(flat_results_list) else rslt_names <- 1
                                  rslt_vec <- rep(rslt_names, rslt_lengths)

                                  # Create the formatted data.frame
                                  # Another method could be: unlist(purrr::map_depth(self$content, 4, 'id'), use.names = FALSE)
                                  ids <- purrr::list_c(purrr::map(flat_results_list, ~purrr::map_chr(., ~purrr::pluck(., 'id'))))
                                  modified <- purrr::list_c(purrr::map(flat_results_list, ~purrr::map_chr(., ~purrr::pluck(., 'modified'))))

                                  self$content <- data.frame(result = rslt_vec,
                                                             id = ids,
                                                             modified = modified)
                                }
                              ),
                              private = list(
                                create_batch_list = function(commit = NULL, version = NULL, name = NULL, ecosystem = NULL, purl = NULL) {
                                  list(commit = commit,
                                       version = version,
                                       package = list(name = name, ecosystem = ecosystem, purl = purl),
                                       page_token = NULL)
                                },

                                # Iterator for OSV pagination tokens
                                iterate_osv_page = function(resp, req) {

                                  json_body <- httr2::resp_body_json(resp)

                                  # Handle results list
                                  json_body <- purrr::list_flatten(json_body, name_spec = '')

                                  # Grab token for each query made to results
                                  tokens <- purrr::map_depth(json_body, 1, 'next_page_token')

                                  # Break out if all tokens are NULL
                                  nulls <- purrr::list_c(purrr::map_depth(tokens, 1, is.null))
                                  if(all(nulls)) return(NULL)

                                  # Customization to httr2 function to adjust request object data... for only those that have them
                                  req$body$data$queries <- purrr::map2(req$body$data$queries[!nulls], tokens[!nulls],
                                                                       function(x, y) {
                                                                         utils::modifyList(x, list(page_token = y), keep.null = TRUE)
                                                                         })
                                  req

                                },

                                # Ensure any paginated responses are reassigned to the correct index and appended
                                # Assign back to a single results flag
                                collapse_paged = function(json_body) {

                                  # Helper function to grab index
                                  extract_token_positions <- function(x) {
                                    tokens <- purrr::map_depth(x, 1, 'next_page_token')
                                    purrr::list_c(purrr::map_depth(tokens, 1, is.null))
                                  }

                                  # Function to perform the reducing (specifically bind vulns, dont care about the page_token at this point)
                                  reduce_f <- function(x, y) {
                                    log_x <- extract_token_positions(x = x)
                                    x[!log_x] <- purrr::map2(x[!log_x], y,
                                                             function(x, y) {
                                                               x$vulns <- append(x$vulns, y$vulns)
                                                               x
                                                             })
                                    x
                                  }

                                  # Reduce backwards based upon how the queries are called and ensure index traced back based on token presence
                                  list(results = purrr::reduce(json_body, reduce_f, .dir = 'backward'))
                                }
                              )
)
