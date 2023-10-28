#' Create list of packages identified in OSV database
#'
#'
#' @details
#' This is the core calculation to extract details from the database. As such, if
#' you set a \code{future::plan()} for parallelization, that will be respected via the
#' \code{furrr} package. The default will be to run sequentially.
#'
#' NOTE: Currently, returns more packages than just subset if using query approach (all packages under vulnerability found). May require subset after returned.
#'
#' @param vulns_list A list of vulnerabilities created via \code{query_osv}; if NA will pull entire database based upon \code{ecosystem} parameter.
#' @param ecosystem Character value of either 'PyPI' or 'CRAN'.
#' @param delim The deliminator to separate the package and version details.
#' @param as.data.frame Boolean value to determine if a data.frame should be created instead of a list.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#' @param clear_cache Boolean value, to force clearing of the existing cache upon exiting function.
#'
#' @returns A vector object containing the package and version details; if \code{as.data.frame} is selected
#' this vector will be reformatted into a \code{data.frame} object.
#'
#' @examplesIf interactive()
#'
#' pypi_vul <- create_osv_list()
#' writeLines(pypi_vul, file.path(tempdir(), 'pypi_vul.txt'))
#'
#' cran_vul <- create_osv_list(ecosystem = 'CRAN', delim = ',')
#' writeLines(cran_vul, file.path(tempdir(), 'cran_vul.csv'))
#'
#' # Use from query instead of entire database
#' pkg_vul <- osv_query(c('dask', 'dash'), ecosystem = c('PyPI', 'PyPI'))
#' create_osv_list(vulns_list = pkg_vul)
#'
#' \dontrun{
#' # In parallel
#' future::plan(multisession, workers = 4)
#' pypi_vul <- create_osv_list()
#' future::plan(sequential)
#' }
#'
#' @export
create_osv_list <- function(vulns_list = NULL, ecosystem = 'PyPI', delim = '\t', as.data.frame = FALSE, refresh = FALSE, clear_cache = FALSE) {

  # Logic to switch file or memory based creation
  file_flag <- is.null(vulns_list)
  # file_flag <- tryCatch(all(file.exists(vulns_list)),
  #                       error = function(e) {
  #                         message('Input was not a filepath, assuming JSON in memory')
  #                         FALSE
  #                         })

  if(is.null(vulns_list)) {
    dir_loc <- download_osv(ecosystem = ecosystem, refresh = refresh)
    vulns_list <- list.files(dir_loc$dl_dir, '*.json', full.names = TRUE)

    on.exit({
      unlink(dir_loc$dl_dir, recursive = TRUE, force = TRUE)
      if(clear_cache) unlink(dir_loc$osv_cache, force = TRUE)
    }, add = TRUE)
  }

  # Run in parallel if plan set by user, otherwise its sequential
  extracted_details <- furrr::future_map(vulns_list, function(x) extract_vul_info(x, delim = delim, file_flag = file_flag))

  if(as.data.frame) {
    utils::read.table(textConnection(unique(sort(unlist(extracted_details)))),
                      sep = delim,
                      col.names = c('package_name', 'version'))
  } else {
    unique(sort(unlist(extracted_details)))
  }
}

#' Create blacklist commands for Posit Package Manager from OSV data
#'
#' @details
#' Although OSV has many databases for open source software, this function really is
#' only relevant for CRAN/Bioconductor and PyPI.
#'
#' @param osv_list Output from \code{create_osv_list()}.
#' @param delim The delimiter used when creating \code{osv_list}.
#' @param flags Global flag to apply to the rspm commands.
#'
#' @examplesIf interactive()
#' pypi_vul <- create_osv_list(delim = ',')
#' cmd_blist <- create_ppm_blacklist(pypi_vul, delim = ',', flags = '--source=pypi')
#'
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


#' Cross reference a whitelist of packages to a vulnerability database
#'
#' @details
#' Note that some version suffixes may have compatibility issues. For example, the use of
#' *-git as a suffix may not be recognized and may need to be dropped. For more details on
#' PyPI package version naming see \url{https://peps.python.org/pep-0440/}.
#'
#' Due to variations in formatting from the API, not all responses have versions associated and
#' are not directly compatible with this function.
#'
#'
#' @param packages Character vector of package names.
#' @param osv_list OSV data/list created from \code{create_osv_list}.
#' @param ecosystem Determine what ecosystem of OSV list is being used (currently only works with PyPI).
#' @param delim The delimiter used when creating \code{osv_list}.
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
create_ppm_xref_whitelist <- function(packages, osv_list, ecosystem = 'PyPI', delim = '\\t', version_placeholder = ' ') {

  if(ecosystem != 'PyPI') stop('This function currently only works for PyPI repos') else warning('This function currently only works for PyPI repos')

  packages <- data.frame(package_name = normalize_pypi_pkg(packages))

  # If was using the non-data.frame format, convert to it for merges...
  if(!is.data.frame(osv_list)) {
    osv_list <-  utils::read.table(textConnection(osv_list),
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
