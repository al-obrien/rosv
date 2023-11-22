#' Download vulnerabilities from the OSV database
#'
#' Use vulnerability IDs and/or an ecosystem name to download vulnerability files from OSV GCS buckets.
#'
#' @details
#' Although the end-result will be similar to the other API functions, this one specifically downloads .zip or
#' .json files from the OSV GCS buckets. As a result, it has two main benefits. First, it can download the entire set
#' of vulnerabilities listed for an ecosystem. Second, it has options to save the vulnerability files to disk. The
#' files are saved to the R session's temp space, as defined by the environment variable \code{ROSV_CACHE_GLOBAL}.
#'
#' Any ecosystems listed \href{https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt}{here} can be downloaded.
#' Only one ecosystem can be provided at a time.
#'
#' @param vuln_ids Vector of vulnerability IDs (optional).
#' @param ecosystem Ecosystem package lives within (must be set).
#' @param parse Boolean value to set if the content field should be parsed from JSON list format.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#' @param download_only Boolean value to determine if only the JSON files should be downloaded to disk.
#'
#' @returns An R6 object containing API query contents.
#'
#' @examplesIf interactive()
#' vulns <- osv_download("RSEC-2023-8", "CRAN")
#' get_content(vulns)
#'
#' # Clean up
#' try(clear_osv_cache())
#'
#' @export
osv_download <- function(vuln_ids = NULL, ecosystem, parse = TRUE, cache = TRUE, download_only = FALSE) {

  if(cache) {
    .osv_download_cache(vuln_ids = vuln_ids,
                        ecosystem = ecosystem,
                        parse = parse,
                        download_only = download_only)
  } else {
    .osv_download(vuln_ids = vuln_ids,
                  ecosystem = ecosystem,
                  parse = parse,
                  download_only = download_only)
  }
}

#' @describeIn osv_download Internal function to run \code{osv_download} without caching.
.osv_download <- function(vuln_ids = NULL, ecosystem, parse = TRUE, download_only = FALSE) {

  vulns <- RosvDownload$new(vuln_ids = vuln_ids, ecosystem = ecosystem)

  vulns$download()

  if(download_only) return(vulns)

  vulns$run()

  if(parse) vulns$parse()

  vulns
}


#' @describeIn osv_download Internal function to run a memoise and cached version of \code{osv_download}.
.osv_download_cache <- function(vuln_ids = NULL, ecosystem, parse = TRUE, download_only = FALSE) {
  # Placeholder for documentation
}
