#' R6 Class for OSV Vulns Endpoint
#'
#' @description
#' An R6 class to provide a lower-level interface to the vulnerability
#' endpoint of the OSV API.
#'
#'
#' @param vuln_ids Character vector of vulnerability IDs.
#'
#' @export
RosvVulns <- R6::R6Class('RosvVulns',
                         inherit = RosvQuery1,
                         public = list(

                           #' @description
                           #' Set the core request details for subsequent use when called in \code{run()} method.
                           initialize = function(vuln_ids) {

                             stopifnot(is.character(vuln_ids))

                             # Perform request, get response
                             req <- private$core_query('vulns')
                             reqs <- purrr::map(vuln_ids, function(x) httr2::req_url_path_append(req, x))

                             self$request <- reqs
                           },

                           #' @description
                           #' Perform the request and return response for OSV API call.
                           run = function() {

                             resps <- purrr::map(self$request, httr2::req_perform)

                             # Assign to main variables
                             self$content <- purrr::map(resps, httr2::resp_body_json)
                             self$response <- resps
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

                           # Placeholder for future use, override base class
                           validate_query = function() {
                             NULL
                           }
                         )
)
