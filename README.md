
<!-- README.md is generated from README.Rmd. Please edit that file -->

# rosv <a href="https://al-obrien.github.io/rosv/"><img src="man/figures/logo.png" align="right" height="139" alt="rosv website" /></a>

<!-- badges: start -->

[![CRAN
status](https://www.r-pkg.org/badges/version/rosv)](https://CRAN.R-project.org/package=rosv)
[![R-CMD-check](https://github.com/al-obrien/rosv/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/al-obrien/rosv/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/al-obrien/rosv/branch/master/graph/badge.svg)](https://app.codecov.io/gh/al-obrien/rosv?branch=master)
<!-- badges: end -->

## Overview

The {rosv} package is an API client to the [Open Source Vulnerability
(OSV) database](https://osv.dev/). Both high and low level functions are
available to query the database for vulnerabilities in package
repositories across various open source ecosystems such as CRAN,
Bioconductor, PyPI, and many more. Queries made against the OSV database
are useful to check for package vulnerabilities (including by specific
versions) enumerated in package management files such as
`requirements.txt` (Python) and `renv.lock` (R).

Various helper functions assist in the administration of [Posit Package
Manager](https://packagemanager.posit.co/client/#/) or similar services.
Packages can be routinely examined for new vulnerabilities which aide in
the creation and updating of curated repositories as well as assigning
block lists.

More details about the OSV project and associated API can be found here:
<https://google.github.io/osv.dev/>.

## Installation

``` r
install.packages('rosv')
library(rosv)
```

For the latest development version, you can install {rosv} from GitHub:

``` r
remotes::install_github('al-obrien/rosv')
```

## Basic usage

Provide a package name and related ecosystem to fetch any identified
vulnerabilities.

``` r
osv_query('dask', ecosystem = 'PyPI')
```

Multiple packages can be queried at the same time and across ecosystems.

``` r
osv_query(c('dask', 'readxl', 'dplyr'),
          ecosystem = c('PyPI', 'CRAN', 'CRAN'))
```

## Development notes

{rosv} is still a young project. There are plans to extend its use.
Currently it uses R6 classes for its low-level interface to the OSV API.
Pagination functionality will be added once it is offered by {httr2},
which at time of writing is available but experimental. There are also
plans to have more types of returned details and parsing of content.
