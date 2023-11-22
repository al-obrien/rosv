# rosv (development version)

* Upgraded to {httr2} 1.0.0
* Upgraded tests with {httptest2} 1.0.0
* Implemented pagination as core functionality in low-level functions (e.g. `RosvQueryBatch()`)
* Remove page_token parameter from mid-level functions, all handled at low-level automatically.
* Use `httr2::req_perform_sequential()` for the `RosvVulns()` methods to get build-in helpers not 
available in `purrr::map()` alone.
* Add `osv_scan()` as a high-level function to scan various components of a project (focus on R project content).
* Add `osv_count_vulns()` to return the number of vulnerabilities a package is associated with.
* Add groupings to pkgdown reference tab
* Add example outputs for getting started vignette
* Add missing R6 dependency and specify more specific minimum versions
* Overhaul `download_osv()` to use R6 objects and memoise for core caching functionality
* List creation functions now use data.frames specifically and have to be created by `osv_query()`.
* Rename `download_osv()` to `osv_download()` to further standardize names 
* `osv_query()` is now central to all high level queries and gains functionality via `osv_download()` to access all vulnerabilities by ecosystem
* Corrected input not being de-duplicated in certain situations for `create_osv_list()`
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
