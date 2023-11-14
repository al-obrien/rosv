with_mock_dir('osv_vulns_req', {
  test_that("Can run mid level vulns query...", {

    expect_true(is_rosv(osv_vulns("RSEC-2023-8", parse = FALSE)))
    expect_true(is_rosv(osv_vulns("RSEC-2023-8", parse = TRUE)))
    expect_true(is_rosv(osv_vulns("RSEC-2023-8", cache = TRUE)))
    expect_true(is_rosv(osv_vulns("RSEC-2023-8", cache = FALSE)))

    expect_true(is_rosv(osv_vulns(c("RSEC-2023-8", "PYSEC-2021-387"), parse = FALSE)))
    expect_true(is_rosv(osv_vulns(c("RSEC-2023-8", "PYSEC-2021-387"), parse = TRUE)))
    expect_true(is_rosv(osv_vulns(c("RSEC-2023-8", "PYSEC-2021-387"), cache = TRUE)))
    expect_true(is_rosv(osv_vulns(c("RSEC-2023-8", "PYSEC-2021-387"), cache = FALSE)))

  })
})
