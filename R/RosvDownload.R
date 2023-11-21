#' R6 Class for OSV Database Downloads
#'
#' @description
#' An R6 class to provide a lower-level interface to download from the OSV database GCS buckets.
#'
#' @details
#' If no vulnerability IDs are provided, the entire set are downloaded from the ecosystems all.zip file.
#' Caching is performed during the \code{run()} operation; this downloads the JSON files to the R session's
#' temporary folder as dictated by the environment variable \code{ROSV_CACHE_GLOBAL}. Due to its similarity
#' in parsing process, it simply inherits the method from the parent class \code{RosvQuery1}.
#'
#' @param vuln_ids Commit hash to query against (do not use when version set).
#' @param ecosystem Ecosystem package lives within (must be set if using \code{name}).
#' @param cache Boolean value to determine if the downloaded files should be cached.
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

                              #' @field request The URLs to request downloaded files.
                              request = NULL,

                              #' @description
                              #' Set the core request details for subsequent use when called in \code{run()} method.
                              initialize = function(vuln_ids = NULL,
                                                    ecosystem) {

                                gcs_bucket <- 'https://osv-vulnerabilities.storage.googleapis.com'

                                self$ecosystem <- check_ecosystem(ecosystem)
                                self$time_stamp <- Sys.time()
                                self$date_stamp_hash <- digest::digest(as.Date(self$time_stamp))

                                self$osv_cache_dir <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), paste0(self$ecosystem, '-', self$date_stamp_hash))

                                if(!is.null(vuln_ids)) {
                                  self$request <- file.path(gcs_bucket, self$ecosystem, paste0(vuln_ids, '.json'))
                                } else {
                                  self$request <- file.path(gcs_bucket, self$ecosystem, 'all.zip')
                                }


                              },

                              #' @description
                              #' Perform the downloads and save if caching. Entire contents of
                              #' each vulnerability file will be loaded into the R session. Subsequent use
                              #' of the \code{parse()} method will shrink the memory footprint as not all contents
                              #' will be carried across.
                              run = function(cache = TRUE) {

                                # Caching...
                                if(cache) {

                                  if(!dir.exists(self$osv_cache_dir)) dir.create(self$osv_cache_dir)

                                  if(!is.null(self$vuln_ids)) {

                                    osv_cache_files <- file.path(self$osv_cache_dir, paste0(vuln_ids, '.json'))
                                    not_cached_vulns <- !file.exists(osv_cache_files)

                                    purrr::walk2(self$request[not_cached_vulns],
                                                 osv_cache_files[not_cached_vulns],
                                                 function(x, y) utils::download.file(x, y))

                                    self$content <- furrr::future_map(osv_cache_files,
                                                                      function(x) jsonlite::read_json(x))

                                  } else {
                                    all_zip <- file.path(self$osv_cache_dir, 'all.zip')

                                    # Will only download if not already present as all.zip, otherwise simply unzips and loads
                                    self$content <- private$osv_zip_operation(self$request,
                                                                              self$osv_cache_dir,
                                                                              all_zip)
                                  }

                                  # Not caching...
                                } else {

                                  # Load all JSON into list from URLs
                                  if(!is.null(self$vuln_ids)) {
                                    self$content <- furrr::future_map(self$vuln_ids,
                                                                      function(x) jsonlite::read_json(x))

                                    # Temporary download, unzip and then load all JSON before wiping out (file should never exist at start)
                                  } else {

                                    temp_path <- file.path(Sys.getenv('ROSV_CACHE_GLOBAL'), 'TEMP')
                                    temp_file <- file.path(temp_path, 'all.zip')

                                    # Clear if TEMP wasnt cleaned up before and remake...
                                    if(dir.exists(temp_path)) unlink(temp_path, recursive = TRUE, force = TRUE)
                                    dir.create(temp_path)

                                    # Remove as caching not being done.
                                    on.exit(unlink(temp_path, recursive = TRUE, force = TRUE),
                                            add = TRUE)

                                    self$content <- private$osv_zip_operation(self$request, temp_path, temp_file)

                                  }
                                }
                              },

                              #' @description
                              #' Print basic details of query object to screen.
                              #' @param ... Reserved for possible future use.
                              print = function(...) {
                                cat('Request(s) made to:', self$request , '\n')

                              }
                            ),

                            # Core operation to download, extract, and load JSON files from all.zip files into memory
                            private = list(
                              osv_zip_operation = function(req, path, file_name) {

                                if(!file.exists(file_name)) {
                                  message('Downloading all.zip from OSV database...')
                                  utils::download.file(url = req,
                                                       destfile = file_name)
                                }

                                utils::unzip(file_name, exdir = path)
                                furrr::future_map(list.files(path, '\\.json$', full.names = TRUE),
                                                  function(x) jsonlite::read_json(x))

                              }
                            )
)

