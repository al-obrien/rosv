
<!-- README.md is generated from README.Rmd. Please edit that file -->

# rosv

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
packages listed on the OSV database.

``` r
library(rosv)

# PUll the PyPI vulnerability data
pypi_vul <- create_osv_list(ecosystem = 'pypi')
pypi_vul

# Query one package in PyPI
pkg_vul <- osv_query('dask', ecosystem = 'PyPI')
create_osv_list(pkg_vul)
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

{rosv} is still a young project. There are plans to extend its use to
other ecosystems. Furthermore, to support any future growth, the project
structure will likely leverage R6 classes.
