with_mock_dir('vulns_request', {
  test_that("Can create a well-formed RosvVulns object...", {

    # For single input
    vulns <- RosvVulns$new(c('RSEC-2023-6'))
    vulns$run()
    expect_equal(vulns$request[[1]]$url,'https://api.osv.dev/v1/vulns/RSEC-2023-6')

    # For >1 input
    vulns <- RosvVulns$new(c('RSEC-2023-6', 'GHSA-jq35-85cj-fj4p'))
    vulns$run()
    expect_equal(vulns$request[[1]]$url,'https://api.osv.dev/v1/vulns/RSEC-2023-6')
    expect_equal(vulns$request[[2]]$url,'https://api.osv.dev/v1/vulns/GHSA-jq35-85cj-fj4p')
  })
})

without_internet({
  test_that("Check error checking on RosvVulns objects...", {

    # Must be character vector
    expect_error(RosvVulns$new(vuln_ids = 11111))
    expect_error(RosvVulns$new(vuln_ids = NA))
    expect_no_error(RosvVulns$new(vuln_ids = c('RSEC-2023-6', NA)))

  })
})
