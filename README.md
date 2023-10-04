
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

## Example

The most basic usage of {rosv} is to pull all versions of PyPI or CRAN
packages listed on the OSV database.

``` r
library(rosv)
pypi_vul <- create_osv_list()
pypi_vul
```
