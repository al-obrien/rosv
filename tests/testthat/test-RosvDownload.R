without_internet({
  test_that("Can create a well-formed RosvDownload object...", {
    rosv_dl_obj <- RosvDownload$new('RSEC-2023-6', ecosystem = 'CRAN')
    expect_equal(rosv_dl_obj$request, "https://osv-vulnerabilities.storage.googleapis.com/CRAN/RSEC-2023-6.json")

    rosv_dl_obj_all <- RosvDownload$new(ecosystem = 'CRAN')
    expect_equal(rosv_dl_obj_all$request, "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip")
  })
})

without_internet({
  test_that("Check error checking on RosvDownload objects...", {

    # Must be character vector and ecosystem provided
    expect_error(RosvDownload$new(vuln_ids = 11111))
    expect_error(RosvDownload$new(vuln_ids = NA_character_))
    expect_error(RosvDownload$new(vuln_ids = c('RSEC-2023-6', NA_character_)))
    expect_error(RosvDownload$new(vuln_ids = c('RSEC-2023-6', 'RSEC-2023-6'), ecosystem = 'cRAN'))
    expect_no_error(RosvDownload$new(vuln_ids = c('RSEC-2023-6', 'RSEC-2023-6'), ecosystem = 'CRAN'))

  })
})
