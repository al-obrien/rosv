#' Extract key OSV information from JSON
#'
#' Use the downloaded JSON dataset from OSV and extract key details on package and versions listed.
#' Packages that do not have a listed version will have a blank space as the default placeholder.
#' This makes it easier for \code{strsplit} to operate on the string in other steps,
#' which will not perform as expected without some value coming after the delimiter.
#'
#' @param input File path to the folder or API response content containing the OSV JSON info
#' @param delim The deliminator to separate the package and version details.
#' @param version_placeholder Value to fill if no versions are listed for package.
extract_vul_info <- function(input, delim = '\t', version_placeholder = ' ') {

  file_check <- tryCatch(file.exists(pkg_vul),
                         error = function(e) {
                           message('Input was not a filepath, assuming JSON in memory')
                           FALSE
                           })

  if(file_check) {
    # Load from a file (if it exists), parse accordingly for affected set
    aff_pkgs <- purrr::pluck(jsonlite::read_json(input), 'affected')
  } else {
    # If not a file, assume its API response, and parse as such (batch needs to be parsed similar)
    aff_pkgs <- purrr::pluck(input, 1, 'affected')
  }

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
#' @param vulns_list A list of vulnerabilities created via \code{query_osv}; if NA will pull entire database based upon \code{ecosystem} parameter.
#' @param ecosystem Character value of either 'pypi' or 'cran'.
#' @param delim The deliminator to separate the package and version details.
#' @param as.data.frame Boolean value to determine if a data.frame should be created instead of a list.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#' @param clear_cache Boolean value, to force clearing of the existing cache upon exiting function.
#'
#' @examples
#' \dontrun{
#' pypi_vul <- create_osv_list()
#' writeLines(pypi_vul, 'pypi_vul.txt')
#'
#' cran_vul <- create_osv_list(ecosystem = 'cran', delim = ',')
#' writeLines(cran_vul, 'cran_vul.csv')
#'
#' # In parallel
#' future::plan(multisession, workers = 4)
#' pypi_vul <- create_osv_list()
#' future::plan(sequential)
#' }
#' @export
create_osv_list <- function(vulns_list = NULL, ecosystem = 'pypi', delim = '\t', as.data.frame = FALSE, refresh = FALSE, clear_cache = FALSE) {
  if(is.null(vulns_list)) {
    dir_loc <- download_osv(ecosystem = ecosystem, refresh = refresh)
    vulns_list <- list.files(dir_loc$dl_dir, '*.json', full.names = TRUE)

    on.exit({
      unlink(dir_loc$dl_dir, recursive = TRUE, force = TRUE)
      if(clear_cache) unlink(dir_loc$osv_cache, force = TRUE)
    }, add = TRUE)
  }

  # Run in parallel if plan set by user, otherwise its sequential
  extracted_details <- furrr::future_map(vulns_list, function(x) extract_vul_info(x, delim = delim))

  if(as.data.frame) {
    read.table(textConnection(unique(sort(unlist(extracted_details)))),
               sep = delim,
               col.names = c('package_name', 'version'))
  } else {
    unique(sort(unlist(extracted_details)))
  }
}

#' Create blacklist commands for Posit Package Manager from OSV data
#'
#' @param osv_list Output from \code{create_osv_list()}.
#' @param delim The delimiter used when creating \code{osv_list}.
#' @param flags Global flag to apply to the rspm commands.
#'
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

#' Normalize package name to PyPI expectation
#'
#' Perform some formatting as PyPI is case insensitive and underscore, period, and hyphens
#' as long runs are not recognized (- is same as --).
#'
#' @param pkg_name Vector of package names.
#'
normalize_pypi_pkg <- function(pkg_name) {

  pypi_pattern <- "^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$"
  if(!all(grepl(x = pkg_name, pattern = pypi_pattern, ignore.case = TRUE))) {
    stop('An invalid package name for Python has been provided')
  }

  tolower(gsub(x = pkg_name, "[-_.]+", replacement = "-"))

}

#' Cross reference a whitelist of packages to a vulnerability database
#'
#' @details
#' Note that some version suffixes may have compatibility issues. For example, the use of
#' *-git as a suffix may not be recognized and may need to be dropped. For more details on
#' PyPI package version naming see \url{https://peps.python.org/pep-0440/}.
#'
#'
#' @param packages Character vector of package names.
#' @param osv_list OSV data/list created from \code{create_osv_list}.
#' @param ecosystem Determine what ecosystem of OSV list is being used (currently only works with pypi).
#' @param version_placeholder Value used when creating the \code{osv_list} from \code{create_osv_list}.
#' @seealso \href{https://packaging.python.org/en/latest/specifications/name-normalization/}{PyPI package normalization}
#' @examples
#' \dontrun{
#' python_pkg <- c('dask', 'tensorflow', 'keras')
#' pypi_vul <- create_osv_list(as.data.frame = TRUE)
#' xref_pkg_list <- create_ppm_xref_whitelist(python_pkg, pypi_vul)
#' writeLines(xref_pkg_list, 'requirements.txt')
#' }
#' @export
create_ppm_xref_whitelist <- function(packages, osv_list, ecosystem = 'pypi', version_placeholder = ' ') {

  if(ecosystem != 'pypi') stop('This function currently only works for pypi repos') else warning('This function currently only works for pypi repos')

  packages <- data.frame(package_name = normalize_pypi_pkg(packages))

  # If was using the non-data.frame format, convert to it for merges...
  if(!is.data.frame(osv_list)) {
    osv_list <-  read.table(textConnection(osv_list),
                            sep = delim,
                            col.names = c('package_name', 'version'))
  }

  # Left join to provided
  packages_vul <- merge(packages, osv_list, by = 'package_name', all.x = TRUE, all.y = FALSE)

  # Categorize package vul types
  packages_vul$type <- NA
  packages_vul[is.na(packages_vul$version),'type'] <- 'ALLOW'
  packages_vul[is.na(packages_vul$type) & packages_vul$version == version_placeholder, 'type'] <- 'BLOCK'
  packages_vul[is.na(packages_vul$type), 'type'] <- "VERSION"

  # Remove all with a block name
  block_pkg <- packages_vul$package_name[packages_vul$type == 'BLOCK']
  packages_vul <- packages_vul[!(packages_vul$package_name %in% block_pkg),]

  if(nrow(packages_vul) > 0) {

  # Generate version exclusion
  exl_v <- lapply(split(packages_vul[packages_vul$type == 'VERSION', 'version'],
                        packages_vul[packages_vul$type == 'VERSION', 'package_name']),
                  function(x){
                    version_glue <- paste0(x, collapse = ', != ')
                  })
  exl_v <- paste0(names(exl_v), ' != ', exl_v)

  # Add to allow list
  xref_pkgs <- c(packages_vul[packages_vul$type == 'ALLOW', 'package_name'],
                 exl_v)
  return(xref_pkgs)
  }

  packages_vul[packages_vul$type == 'ALLOW', 'package_name']

}

# Incomplete... for helping if affected array is nested at different depths in API resp
locate_min_depth <- function(list, target) {

  max_search_depth <- purrr::pluck_depth(list)
  # if(max_search_depth > 100) stop('Will not search larger than 100 steps deep in a list')
  # if(max_search_depth < 1 ) stop('Max search depth must be larger than 0')

  flag <- NULL
  i = 1

  while(is.null(flag)) {
    search_rslt <- unlist(purrr::map_depth(list, i, target, .ragged = TRUE))
    i <- i + 1
    flag <- search_rslt
  }

  for(i in seq(1:max_search_depth)) {

  }

  unlisted <- unlist(list, recursive = TRUE)
  names(unlisted)

  # Assumes each depth has a name...
  split_names <- strsplit(names(unlist(list, recursive = TRUE)), split = '\\.')
  min(unlist(lapply(split_names, function(x) which(x == target))), na.rm = TRUE)
}
