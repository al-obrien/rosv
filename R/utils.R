#' Download helper for OSV data
#'
#' Helper function to assist in downloading vulnerabilities information from OSV database.
#'
#' @param type Character value of either 'pypi' or 'cran'.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
download_osv <- function(type = 'pypi', refresh = FALSE) {

  # Specific database URLs
  vul_url <- if(type == 'pypi') {
    'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip'
  } else if (type == 'cran') {
    'https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip'
  }

  # Cache setup, only DL zip if not done today or in live session
  time_stamp <- Sys.time()
  date_stamp_hash <- digest::digest(as.Date(time_stamp))
  osv_cache <- file.path(tempdir(), paste0(type, '-', date_stamp_hash, '.zip'))

  if(!file.exists(osv_cache) || refresh) {
    message('Downloading from OSV online database...')
    download.file(url = vul_url, destfile = osv_cache)
  }

  # Unzip for use...
  dl_dir <- file.path(tempdir(), paste0(type,'-unzipped-',date_stamp_hash))
  unzip(osv_cache, exdir = dl_dir)

  return(list('osv_cache' = osv_cache,
              'dl_dir' = dl_dir))
}

#' Extract key OSV information from JSON
#'
#' Use the downloaded JSON dataset from OSV and extract key details on package and versions listed.
#'
#' @param file File path to the folder containing the OSV JSON files.
#' @param delim The deliminator to separate the package and version details.
#' @param version_placeholder Value to fill if no versions are listed for package.
extract_vul_info <- function(file, delim = '\t', version_placeholder = ' ') {
  aff_pkgs <- purrr::pluck(jsonlite::read_json(file), 'affected')
  pkg_names <- purrr::map(aff_pkgs, function(x) purrr::pluck(x, 'package', 'name'))
  pkg_versions <- purrr::map(aff_pkgs, function(x) purrr::pluck(x, 'versions'))
  if(length(pkg_versions) == 1 && length(pkg_versions[[1]]) < 1) pkg_versions <- version_placeholder
  unlist(purrr::map2(pkg_names, pkg_versions, function(x,y) paste(x, y, sep = delim)))
}

#' Create list of packages identified in OSV database
#'
#' @details
#' This is the core calculation to extract details from the database. As such, if
#' you set a \code{future::plan()} for parallelization, that will be respected via the
#' \code{furrr} package. The default will be to run sequentially.
#'
#'
#' @param type Character value of either 'pypi' or 'cran'.
#' @param delim The deliminator to separate the package and version details.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#' @param clear_cache Boolean value, to force clearing of the existing cache upon exiting function.
#'
#' @examples
#' \dontrun{
#' pypi_vul <- create_osv_list()
#' writeLines(pypi_vul, 'pypi_vul.txt')
#'
#' cran_vul <- create_osv_list(type = 'cran', delim = ',')
#' writeLines(cran_vul, 'cran_vul.csv')
#'
#' # In parallel
#' future::plan(multisession, workers = 4)
#' pypi_vul <- create_osv_list()
#' future::plan(sequential)
#' }
#' @export
create_osv_list <- function(type = 'pypi', delim = '\t', refresh = FALSE, clear_cache = FALSE) {
  dir_loc <- download_osv(type = type, refresh = refresh)
  vul_files <- list.files(dir_loc$dl_dir, '*.json', full.names = TRUE)

  on.exit({
    unlink(dir_loc$dl_dir, recursive = TRUE, force = TRUE)
    if(clear_cache) unlink(dir_loc$osv_cache, force = TRUE)
  }, add = TRUE)

  # Run in parallel if plan set by user, otherwise its sequential
  extracted_details <- furrr::future_map(vul_files, function(x) extract_vul_info(x, delim = delim))
    unique(sort(unlist(extracted_details)))
}

#' Create blacklist commands for Posit Package Manager from OSV data
#'
#' @param osv_list Output from \code{create_osv_list()}.
#' @param delim The deliminter used when creating \code{osv_list}.
#' @param flags Global flag to apply to the rspm commands.
#' @examples
#' \dontrun{
#' pypi_vul <- create_osv_list(delim = ',')
#' cmd_blist <- create_ppm_blacklist(pypi_vul, delim = ',', flags = '--source=pypi')
#' }
#' @export
create_ppm_blacklist <- function(osv_list, delim, flags = NULL) {
  split_list <- unlist(strsplit(osv_list, delim)) #strsplit doesnt recognize empty after delim, perhaps use str_split
  cmd_out <- paste0('rspm create blocklist-rule ',
                    '--package-name=', split_list[seq(1,length(split_list), by = 2)])

  versions <- split_list[seq(2,length(split_list), by = 2)]
  inx_v <- versions != ' '

  cmd_out[inx_v] <- paste0(cmd_out[inx_v], ' --version=', versions[inx_v])
  if(!is.null(flags)) cmd_out <- paste(cmd_out, flags)
  cmd_out
}
