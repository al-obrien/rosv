# rosv 0.5.1

* Missing :: for some functions (e.g. `purrr::list_rbind()`)

# rosv 0.5.0

## New features
* Implemented pagination as core functionality in low-level functions (e.g. `RosvQueryBatch()`)
* Add `osv_scan()` as a high-level function to scan various components of a project (focused on R project content)
* Add `osv_count_vulns()` to return the number of vulnerabilities a package is associated with
* `osv_query()` is now central to all high level queries and gains functionality via `osv_download()` to access all vulnerabilities by ecosystem

## Breaking changes
* Upgraded to {httr2} 1.0.0
* Upgraded tests with {httptest2} 1.0.0
* Overhaul `download_osv()` to use R6 objects and memoise for core caching functionality, 
rename `download_osv()` to `osv_download()` to further standardize names 

## Minor changes, improvements, and fixes
* Use `httr2::req_perform_sequential()` for the `RosvVulns()` methods to get build-in helpers not 
available in `purrr::map()` alone
* Corrected input not being de-duplicated in certain situations for `create_osv_list()`
* Remove page_token parameter from mid-level functions, all handled at low-level automatically
* Add groupings to pkgdown reference tab
* Add example outputs for getting started vignette
* Add missing R6 dependency and specify more specific minimum versions
* List creation functions now use data.frames specifically and have to be created by `osv_query()`
* Allow filtering when downloading all vulnerability files from an ecosystem but other ecosystems with 
the same vulnerability are included (e.g. GHSA-gq4p-4hxv-5rg9)
* Package documentation Rd added

# rosv 0.4.2

* Initial CRAN release

# rosv 0.3.0 (2023-11-01)

* Overhaul on docs, basic tests, and more helper functions
* Add caching mechanism

# rosv 0.2.0 (2023-10-28)

* Update to use of R6 for back-end 

# rosv 0.1.0

* Initial project commits.
