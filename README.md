
<!-- README.md is generated from README.Rmd. Please edit that file -->

# rosv

<!-- badges: start -->

[![R-CMD-check](https://github.com/al-obrien/rosv/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/al-obrien/rosv/actions/workflows/R-CMD-check.yaml)
<!-- badges: end -->

Use R to query the [Open Source Vulnerability (OSV)
database](https://osv.dev/). This can be useful to cross check the
database with packages used in `requirements.txt` (python) or
`renv.lock` files (R). The generated content can also be used to create
block lists for curated repositories with Posit Package Manager. More
details about the OSV project and associated API can be found here:
<https://google.github.io/osv.dev/>

## Installation

You can install {rosv} only from GitHub:

``` r
remotes::install_github('al-obrien/rosv')
```

## Basic Example

The most basic usage of {rosv} is to pull all versions of PyPI or CRAN
packages listed on the OSV database using high-level functions such as
`osv_query()` and `create_osv_list()`.

``` r
library(rosv)

# Query one package in PyPI for vulnerabilities
pkg_vul <- osv_query('dask', ecosystem = 'PyPI')
create_osv_list(pkg_vul)
```

``` r
# Pull the entire set of PyPI vulnerability data
pypi_vul <- create_osv_list(ecosystem = 'PyPI')
pypi_vul
```

## Use API helpers directly

Lower-level functionality is available to return more details about the
API request and response contained within the R6 object. These are more
flexible than their higher-level alternatives.

``` r
# Returns entire response object to parse as you please.
osv_query_1('dask', ecosystem = 'PyPI')

# Returns the vulnerability IDs for packages in list
osv_querybatch('dask', ecosystem = 'PyPI')

# Return vulnerabilities from different ecosystems as vectors
osv_querybatch(c('dask', 'readxl'), ecosystem = c('PyPI', 'CRAN'))

# Grab details by vulns ID
osv_vulns('PYSEC-2021-387')
```

## Creating a cross-referenced whitelist

When using a product such as {miniCRAN} or Posit Package Manager, there
may be corporate requirements to limit what packages users can install.
Although having a whitelist is often recommended, it should either
specify the exact versions that are approved or exclude packages with
known vulnerabilities. Given the amount of packages and versions, this
is often difficult. The following method will take a vector of packages
(from PyPI) and cross-reference against the OSV database. If packages
are identified they are either entirely dropped, or the specific
versions with flagged vulnerabilities are excluded.

``` r
# List of packages of interest
python_pkg <- c('dask', 'tensorflow', 'keras')

# Create the xref whitelist
pypi_vul <- create_osv_list(as.data.frame = TRUE)
xref_pkg_list <- create_ppm_xref_whitelist(python_pkg, pypi_vul)

# Output requirements.txt which can be used with PPM product
writeLines(xref_pkg_list, 'requirements.txt')
```

## Development notes

{rosv} is still a young project. There are plans to extend its use.
Currently it uses R6 classes for its lower-level interface to the OSV
API. Pagination functionality will be added once it is offered by
{httr2}, which at time of writing is available but experimental. There
are also plans to have more types of returned details, such as returning
just the version input for functions like `osv_query()`.
