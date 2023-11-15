# rosv (development version)

* Upgraded to {httr2} 1.0.0
* Upgraded tests with {httptest2} 1.0.0
* Implemented pagination as core functionality in low-level functions (e.g. `RosvQueryBatch()`)
* Remove page_token parameter from mid-level functions, all handled at low-level automatically.
* Use `httr2::req_perform_sequential()` for the `RosvVulns()` methods to get build-in helpers not 
available in `purrr::map()` alone.

# rosv 0.4.2

* Initial CRAN release

# rosv 0.3.0 (2023-11-01)

* Overhaul on docs, basic tests, and more helper functions
* Add caching mechanism

# rosv 0.2.0 (2023-10-28)

* Update to use of R6 for back-end 

# rosv 0.1.0

* Initial project commits.
