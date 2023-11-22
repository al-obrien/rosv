#' List packages identified in the OSV database
#'
#' Create a list of package names and versions based upon vulnerabilities discovered in the OSV database
#' using \code{\link{osv_query}}.
#'
#' @details
#' Requires an object of type \code{rosv_query} created by \code{\link{osv_query}}. This can be
#' a selection of packages or all vulnerabilities for an ecosystem. Depending on use-case, users may
#' prefer the vector based output with pairs of package names and versions separated by a provided value.
#' Since only name and versions are returned, only one ecosystem can be operated on at a time.
#'
#' Please note, the default behaviour of \code{osv_query()} is to return all packages (and versions) across ecosystems
#' associated with discovered vulnerabilities. If a package is discovered across several vulnerabilities it will
#' be listed multiple times, by default, in the returned content. Unlike \code{osv_query()}, \code{create_osv_list()} will
#' further sort and return a unique set of packages. In most circumstances, users will create the
#' \code{rosv_query} (via \code{osv_query()}) with the \code{all_affected} parameter set to \code{FALSE}
#' so that only the package names of interest are returned.
#'
#' @param rosv_query A table of vulnerabilities (created via \code{osv_query()}).
#' @param as.data.frame Boolean value to determine if a data.frame should be returned.
#' @param sort Boolean value to determine if results should be sorted by name and version.
#' @param delim The deliminator to separate the package and version details (ignored if \code{as.data.frame} set to \code{TRUE}).
#' @param NA_value Character value to replace missing versions (typically means all versions impacted).
#'
#' @returns A \code{data.frame()} or vector object containing the package and version details.
#'
#' @seealso \code{\link{osv_query}}
#'
#' @examplesIf interactive()
#'
#' # List of a few PyPI packages in data.frame output
#' pypi_query <- osv_query(c('dask', 'dash', 'aaiohttp'),
#'                         ecosystem = rep('PyPI', 3),
#'                         all_affected = FALSE)
#' pypi_vul <- create_osv_list(pypi_query)
#' file_name1 <- file.path(tempdir(), 'pypi_vul.csv')
#' writeLines(pypi_vul, file_name1)
#'
#' # All CRAN vulns in vector output
#' cran_query <- osv_query(ecosystem = 'CRAN', all_affected = FALSE)
#' cran_vul <- create_osv_list(cran_query, as.data.frame = FALSE, delim = ',')
#' file_name2 <- file.path(tempdir(), 'cran_vul.csv')
#' writeLines(cran_vul, file_name2)
#'
#' # Clean up
#' try(unlink(c(file_name1, file_name2)))
#'
#' @export
create_osv_list <- function(rosv_query = NULL, as.data.frame = TRUE, sort = TRUE, delim = '\t', NA_value = NULL) {

  stopifnot(inherits(rosv_query, 'rosv_query'))
  if(length(unique(rosv_query[, 'ecosystem'])) > 1) stop ('Only operates on vulnerabilities from a single ecosystem at a time.')

  if(!is.null(NA_value)) {
    stopifnot(is.character(NA_value))
    rosv_query[is.na(rosv_query$versions), 'versions'] <- NA_value
  }

  # Keep only unique
  rosv_query <- unique(rosv_query[,c('name', 'versions')])
  if(sort) rosv_query <- rosv_query[order(rosv_query$name, rosv_query$versions),]

  if(as.data.frame) {

    return(rosv_query)

  } else {

    return(paste(rosv_query$name, rosv_query$versions, sep = delim))

  }
}


#' Create blacklist commands for Posit Package Manager
#'
#' Use OSV data accessed via \code{\link{osv_query}} to create blacklist (i.e. blocklist)
#' commands for the Posit Package Manager product.
#'
#' @details
#' Although OSV has many databases for open source software, this function is
#' only relevant for CRAN/Bioconductor and PyPI. To ensure the blacklist is applied to the
#' appropriate target, it is encouraged to specify the name of the source used in your configuration
#' as an additional flag parameter (see examples). Only one ecosystem can be used at a time to ensure
#' there is not a mix of packages across ecosystems applied to incompatible sources.
#'
#' @param rosv_query A table of vulnerabilities (created via \code{osv_query()}).
#' @param flags Global flag to append to commands.
#'
#' @returns Character vector containing blacklist commands.
#'
#' @examplesIf interactive()
#'
#' # Blacklist all CRAN package versions with a listed vulnerability
#' cran_vul <- osv_query(ecosystem = 'CRAN', all_affected = FALSE)
#' cmd_blist <- create_ppm_blacklist(cran_vul, flags = '--source=cran')
#'
#' @export
create_ppm_blacklist <- function(rosv_query, flags = NULL) {

  stopifnot(inherits(rosv_query, 'rosv_query'))
  if(length(unique(rosv_query[, 'ecosystem'])) > 1) stop ('Only operates on vulnerabilities from a single ecosystem at a time.')

  rosv_query <- unique(rosv_query[,c('name', 'versions')])

  cmd_out <- paste0('rspm create blocklist-rule ',
                    '--package-name=', rosv_query$name)

  inx_v <- !is.na(rosv_query$versions)

  cmd_out[inx_v] <- paste0(cmd_out[inx_v], ' --version=', rosv_query$versions[inx_v])
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
#' Although the default output is a \code{\link[base]{data.frame}}, for PyPI packages a \code{requirements.txt} format can be
#' created that defines which versions should not be allowed based upon the cross-referencing performed. This can be
#' useful when curating repositories in Posit Package Manager.
#'
#' @param packages Character vector of package names.
#' @param ecosystem Character vector of ecosystem(s) within which the package(s) exist.
#' @param output_format Type of output to create (default is \code{NULL} for a \code{\link[base]{data.frame}}).
#'
#' @seealso \href{https://packaging.python.org/en/latest/specifications/name-normalization/}{PyPI package normalization}
#' @returns A \code{\link[base]{data.frame}} or character vector containing cross-referenced packages.
#' @examplesIf interactive()
#'
#' # Return xref dataset for CRAN package selection
#' cran_pkg <- c('readxl', 'dplyr')
#' cran_xref <- create_xref_whitelist(cran_pkg, ecosystem = 'CRAN')
#'
#' # Create a requirements.txt with excluded versions
#' python_pkgs <- c('dask', 'aaiohttp', 'keras')
#' xref_pkg_list <- create_xref_whitelist(python_pkgs,
#'                                        ecosystem = 'PyPI',
#'                                        output_format = 'requirements.txt')
#' file_name <- file.path(tempdir(), 'requirements.txt')
#' writeLines(xref_pkg_list, file_name)
#'
#' # Clean up
#' try(unlink(file_name))
#'
#' @export
create_xref_whitelist <- function(packages, ecosystem, output_format = NULL) {

  # Checks...
  ecosystem <- check_ecosystem(ecosystem)
  if(!is.null(output_format)) {
    output_format <- match.arg(output_format, choices = 'requirements.txt', several.ok = FALSE)
    if(ecosystem != 'PyPI' && output_format == 'requirements.txt') stop('The output format is not compatible with the provided ecosystem')
  }

  if(ecosystem == 'PyPI') {
    packages <- unique(data.frame(name = normalize_pypi_pkg(packages)))
  } else {
    packages <- unique(data.frame(name = packages))
  }

  # Pull all vulnerabilities for the cross reference
  osv_list <- create_osv_list(osv_query(name = packages$name, ecosystem = rep(ecosystem, nrow(packages)), all_affected = FALSE),
                               NA_value = '_ALL_')


  # Left join to provided
  packages_vul <- merge(packages, osv_list, by = 'name', all.x = TRUE, all.y = FALSE)

  # Categorize package vul types
  packages_vul$block_rule <- NA
  packages_vul[is.na(packages_vul$versions),'block_rule'] <- 'ALLOW'
  packages_vul[is.na(packages_vul$block_rule) & packages_vul$versions == '_ALL_', 'block_rule'] <- 'BLOCK_ALL'
  packages_vul[is.na(packages_vul$block_rule), 'block_rule'] <- "BLOCK_VERSION"

  if(is.null(output_format)) return(packages_vul)

  # Remove all with a block name
  block_pkg <- packages_vul$name[packages_vul$block_rule == 'BLOCK']
  packages_vul <- packages_vul[!(packages_vul$name %in% block_pkg),]

  if(output_format == 'requirements.txt') {
    if(nrow(packages_vul) > 0) {

      # Generate version exclusion
      exl_v <- lapply(split(packages_vul[packages_vul$block_rule == 'BLOCK_VERSION', 'versions'],
                            packages_vul[packages_vul$block_rule == 'BLOCK_VERSION', 'name']),
                      function(x){
                        version_glue <- paste0(x, collapse = ', != ')
                      })
      exl_v <- paste0(names(exl_v), ' != ', exl_v)

      # Add to allow list
      xref_pkgs <- c(packages_vul[packages_vul$block_rule == 'ALLOW', 'name'],
                     exl_v)
      return(xref_pkgs)
    }

    packages_vul[packages_vul$block_rule == 'ALLOW', 'name']

  }
}
