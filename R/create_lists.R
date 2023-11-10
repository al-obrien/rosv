#' List packages identified in the OSV database
#'
#' Create a list based upon package vulnerabilities discovered in the OSV database.
#'
#' @details
#' If used without assigning \code{rosv_query} parameter, all packages listed in the ecosystem
#' will be referenced. To speed up this creation process for large ecosystems you can set \code{future::plan()}
#' for parallelization; this will be respected via the \code{furrr} package. The default will be to run sequentially.
#'
#' Please note, the default behaviour is to return all packages (and versions) associated with discovered vulnerabilities. Ensure you
#' have properly subset the returned query if not done so via the function parameters. Furthermore, if the package is
#' listed across several vulnerabilities, an additional deduplication step may need to be performed. Furthermore, the \code{clear_cache}
#' parameter is specific to a downloaded set of JSON files, it is not related to caching of specific API queries which happens
#' prior to using this step via functions like \code{query_osv()}.
#'
#' @param rosv_query A table of vulnerabilities (created via \code{query_osv()}); if not set, will pull an ecosystem's entire database.
#' @param ecosystem Character value of ecosystem name (e.g. PyPI or CRAN); should not be set if providing \code{rosv_query}.
#' @param delim The deliminator to separate the package and version details.
#' @param as.data.frame Boolean value to determine if a data.frame should be returned.
#' @param refresh Force refresh of the cache to grab latest details from OSV databases.
#' @param clear_cache Boolean value, to force clearing of the existing cache upon exiting function for downloaded JSON files.
#'
#' @returns A vector object containing the package and version details; if \code{as.data.frame} is selected
#' this vector will be reformatted into a \code{data.frame()} object.
#'
#' @examplesIf interactive()
#'
#' pypi_vul <- create_osv_list(ecosystem = 'PyPI')
#' file_name1 <- file.path(tempdir(), 'pypi_vul.csv')
#' writeLines(pypi_vul, file_name1)
#'
#' cran_vul <- create_osv_list(ecosystem = 'CRAN', delim = ',')
#' file_name2 <- file.path(tempdir(), 'cran_vul.csv')
#' writeLines(cran_vul, file_name2)
#'
#' # Clean up
#' try(unlink(c(file_name1, file_name2)))
#'
#' # Use from query instead of entire database
#' pkg_vul <- osv_query(c('dask', 'dash'), ecosystem = c('PyPI', 'PyPI'))
#' create_osv_list(rosv_query = pkg_vul)
#'
#' @export
create_osv_list <- function(rosv_query = NULL, ecosystem = NULL, delim = '\t', as.data.frame = FALSE, refresh = FALSE, clear_cache = FALSE) {

  # If used downloaded JSONs...
  if(is.null(rosv_query)) {
    stopifnot(!is.null(ecosystem))
    dir_loc <- download_osv(ecosystem = ecosystem, refresh = refresh)
    rosv_query <- list.files(dir_loc$dl_dir, '*.json', full.names = TRUE)

    on.exit({
      unlink(dir_loc$dl_dir, recursive = TRUE, force = TRUE)
      if(clear_cache) unlink(dir_loc$osv_cache, force = TRUE)
    }, add = TRUE)

    # Run in parallel if plan set by user, otherwise its sequential
    extracted_details <- furrr::future_map(rosv_query, function(x) extract_vul_info(x, delim = delim))

    if(as.data.frame) {
      return(utils::read.table(textConnection(unique(sort(unlist(extracted_details)))),
                        sep = delim,
                        col.names = c('name', 'versions')))
    } else {
      return(unique(sort(unlist(extracted_details))))
    }

  # If used a query...
  } else {
    stopifnot(inherits(rosv_query, 'rosv_query'))
    if(as.data.frame) {
      return(rosv_query[,c('name', 'versions')])
    } else {
      return(unique(sort(paste(rosv_query$name, rosv_query$versions, sep = delim))))
    }
  }
}


#' Create blacklist commands for Posit Package Manager
#'
#' Use OSV data to create blacklist (i.e. blocklist) commands for the Posit Package
#' Manager product.
#'
#' @details
#' Although OSV has many databases for open source software, this function is
#' only relevant for CRAN/Bioconductor and PyPI.
#'
#' @param osv_list Output from \code{create_osv_list()}.
#' @param delim The delimiter used from \code{create_osv_list()}.
#' @param flags Global flag to append to commands.
#'
#' @returns Character vector containing blacklist commands.
#'
#' @examplesIf interactive()
#' pypi_vul <- create_osv_list(ecosystem = 'PyPI', delim = ',')
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
#' Search for package names for vulnerability information and selectively drop packages
#' or define specific versions that should not be used in a curated repository.
#'
#' @details
#' Note that some version suffixes may have compatibility issues. For example, the use of
#' *-git as a suffix may not be recognized and may need to be dropped. For more details on
#' PyPI package version naming see \url{https://peps.python.org/pep-0440/}.
#'
#' Due to variations in formatting from the OSV API, not all responses have versions associated and
#' are not directly compatible with this function.
#'
#' @param packages Character vector of package names.
#' @param osv_list OSV data/list created from \code{create_osv_list()}.
#' @param ecosystem Determine what ecosystem of OSV list is being used (currently only works with PyPI).
#' @param delim The delimiter used when creating \code{osv_list}.
#' @param version_placeholder Value used when creating the \code{osv_list} from \code{create_osv_list()}.
#' @param full_table Boolean value to determine if a complete table before dropping packages is returned (helpful for debugging).
#'
#' @seealso \href{https://packaging.python.org/en/latest/specifications/name-normalization/}{PyPI package normalization}
#' @returns Character vector containing the information for a selective requirements.txt file.
#' @examplesIf interactive()
#' python_pkg <- c('dask', 'tensorflow', 'keras')
#' pypi_vul <- create_osv_list(ecosystem = 'PyPI', as.data.frame = TRUE)
#' xref_pkg_list <- create_ppm_xref_whitelist(python_pkg, pypi_vul)
#' file_name <- file.path(tempdir(), 'requirements.txt')
#' writeLines(xref_pkg_list, file_name)
#'
#' # Clean up
#' try(unlink(file_name))
#'
#' @export
create_ppm_xref_whitelist <- function(packages, osv_list, ecosystem = 'PyPI', delim = '\\t', version_placeholder = ' ', full_table = FALSE) {

  if(ecosystem != 'PyPI') stop('This function currently only works for PyPI repos') else warning('This function currently only works for PyPI repos')

  packages <- unique(data.frame(name = normalize_pypi_pkg(packages)))

  # If was using the non-data.frame format, convert to it for merges...
  if(!is.data.frame(osv_list)) {
    osv_list <-  utils::read.table(textConnection(osv_list),
                                   sep = delim,
                                   col.names = c('name', 'versions'))
  }

  # Left join to provided
  packages_vul <- merge(packages, osv_list, by = 'name', all.x = TRUE, all.y = FALSE)

  # Categorize package vul types
  packages_vul$type <- NA
  packages_vul[is.na(packages_vul$versions),'type'] <- 'ALLOW'
  packages_vul[is.na(packages_vul$type) & packages_vul$versions == version_placeholder, 'type'] <- 'BLOCK'
  packages_vul[is.na(packages_vul$type), 'type'] <- "VERSION"

  if(full_table) return(packages_vul)

  # Remove all with a block name
  block_pkg <- packages_vul$name[packages_vul$type == 'BLOCK']
  packages_vul <- packages_vul[!(packages_vul$name %in% block_pkg),]

  if(nrow(packages_vul) > 0) {

    # Generate version exclusion
    exl_v <- lapply(split(packages_vul[packages_vul$type == 'VERSION', 'versions'],
                          packages_vul[packages_vul$type == 'VERSION', 'name']),
                    function(x){
                      version_glue <- paste0(x, collapse = ', != ')
                    })
    exl_v <- paste0(names(exl_v), ' != ', exl_v)

    # Add to allow list
    xref_pkgs <- c(packages_vul[packages_vul$type == 'ALLOW', 'name'],
                   exl_v)
    return(xref_pkgs)
  }

  packages_vul[packages_vul$type == 'ALLOW', 'name']

}
