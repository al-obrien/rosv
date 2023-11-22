#' R6 Class for OSV Database Downloads
#'
#' @description
#' An R6 class to provide a lower-level interface to download from the OSV database GCS buckets.
#'
#' @details
#' If no vulnerability IDs are provided, the entire set is downloaded from the ecosystem's all.zip file.
#' JSON files are downloaded to the R session's temporary folder as dictated by the environment
#' variable \code{ROSV_CACHE_GLOBAL}. Due to its similarity in parsing process, it simply inherits
#' the method from the parent class \code{RosvQuery1}.
#'
#' Any ecosystems listed \href{https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt}{here} can be downloaded.
#'
#' @param vuln_ids Character vector of vulnerability IDs.
#' @param ecosystem Ecosystem package lives within (must be set).
#'
#' @returns An R6 object to operate with data downloaded from the OSV GCS buckets.
#'
#' @seealso \url{https://google.github.io/osv.dev/data/#data-dumps}
#'
#' @examples
#' query <- RosvDownload$new(ecosystem = 'CRAN')
#' query
#' @export
RosvDownload <- R6::R6Class('RosvDownload',
                            inherit = RosvQuery1,
                            public = list(

                              #' @field osv_cache_dir Location of cached vulnerability JSON files.
                              osv_cache_dir = NULL,

                              #' @field content Content from downloading the vulnerabilities.
                              content = NULL,

                              #' @field time_stamp Time stamp associated with run.
                              time_stamp = NULL,

                              #' @field date_stamp_hash Hashed date from time stamp.
                              date_stamp_hash = NULL,

                              #' @field ecosystem The ecosystem used upon creation.
                              ecosystem = NULL,

                              #' @field vuln_ids The vulnerability IDs, if provided.
                              vuln_ids = NULL,

                              #' @field request The URLs to request downloaded files.
                              request = NULL,

                              #' @description
                              #' Set the core request details for subsequent use when called in \code{run()} method.
                              initialize = function(vuln_ids = NULL,
                                                    ecosystem) {

                                if(!is.null(vuln_ids)) {
                                  stopifnot(is.character(vuln_ids))
                                  stopifnot(all(!is.na(vuln_ids)))
                                }

                                stopifnot(is.character(ecosystem))
                                if(length(ecosystem) > 1) stop('Only provide 1 ecosystem at a time.')

                                self$ecosystem <- check_ecosystem(ecosystem)
                                self$vuln_ids <- vuln_ids
                                self$time_stamp <- Sys.time()
                                self$date_stamp_hash <- digest::digest(as.Date(self$time_stamp))

                                gcs_bucket <- 'https://osv-vulnerabilities.storage.googleapis.com'

                                self$osv_cache_dir <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), paste0(self$ecosystem, '-', self$date_stamp_hash))

                                if(!is.null(vuln_ids)) {
                                  self$request <- file.path(gcs_bucket, self$ecosystem, paste0(vuln_ids, '.json'))
                                } else {
                                  self$request <- file.path(gcs_bucket, self$ecosystem, 'all.zip')
                                }


                              },

                              #' @description
                              #' Download vulnerabilities from provided \code{ecosystem} to disk, the location
                              #' is recorded under the \code{osv_cache_dir} field. Will overwrite any existing files
                              #' in the cache.
                              download = function() {

                                if(!dir.exists(self$osv_cache_dir)) dir.create(self$osv_cache_dir)

                                if(!is.null(self$vuln_ids)) {

                                  osv_cache_files <- file.path(self$osv_cache_dir, paste0(self$vuln_ids, '.json'))

                                  cached_vulns <- file.exists(osv_cache_files)
                                  if(any(cached_vulns)) message('Overwriting previously downloaded JSON files...')

                                  purrr::walk2(self$request,
                                               osv_cache_files,
                                               function(x, y) utils::download.file(x, y))

                                } else {

                                  all_zip <- file.path(self$osv_cache_dir, 'all.zip')
                                  if(file.exists(all_zip)) message('Overwriting a previously downloaded all.zip file...')
                                  utils::download.file(url = self$request, destfile = all_zip)
                                  utils::unzip(all_zip, exdir = self$osv_cache_dir)

                                }
                              },

                              #' @description
                              #' Load vulnerabilities to the R session. The entire contents of
                              #' each vulnerability file will be loaded. Subsequent use of the \code{parse()} method
                              #' will shrink the memory footprint as not all contents will be carried across.
                              run = function() {

                                if(!is.null(self$vuln_ids)) {

                                  # Could also just use the request to load directly, but process here is to download first always...
                                  self$content <- furrr::future_map(file.path(self$osv_cache_dir, paste0(self$vuln_ids, '.json')),
                                                                    function(x) jsonlite::read_json(x))


                                } else {

                                  self$content <- furrr::future_map(list.files(self$osv_cache_dir, '\\.json$', full.names = TRUE),
                                                                    function(x) jsonlite::read_json(x))
                                }
                              },

                              #' @description
                              #' Print basic details of query object to screen.
                              #' @param ... Reserved for possible future use.
                              print = function(...) {

                                cat('Request(s) made to:', unique(dirname(self$request)), '\n')
                                cat('Save location: ', self$osv_cache_dir, '\n')
                                cat('Object contents: ', typeof(self$content))

                              }
                            )
)

