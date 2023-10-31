#' Query OSV API for vulnerabilities based on ID
#'
#' Use vulnerability IDs to extract more details information. Usually is paired with \code{osv_querybatch}.
#'
#' @param vuln_ids Vector of vulnerability IDs.
#' @param parse Boolean value to set if the content field should be parsed from JSON list format.
#' @param cache Boolean value to determine if should use a cached version of the function and API results.
#'
#' @returns An R6 object containing API query contents.
#'
#' @examplesIf interactive()
#' vulns <- osv_vulns("RSEC-2023-8")
#' get_content(vulns)
#'
#' @export
osv_vulns <- function(vuln_ids, parse = TRUE, cache = TRUE) {

  if(cache) {
    .osv_vulns_cache(vuln_ids = vuln_ids,
                     parse = parse)
  } else {
    .osv_vulns(vuln_ids = vuln_ids,
               parse = parse)
  }
}

#' @describeIn osv_vulns Internal function to run osv_vulns without caching
.osv_vulns <- function(vuln_ids, parse = TRUE) {

  vulns <- RosvVulns$new(vuln_ids)
  vulns$run()
  if(parse) vulns$parse()

  vulns
}


#' @describeIn osv_vulns Internal function to run a memoise and cached version of osv_vulns
.osv_vulns_cache <- function(vuln_ids, parse = TRUE) {
  # Placeholder for documentation
}
