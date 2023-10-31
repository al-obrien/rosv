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
