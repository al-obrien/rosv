with_mock_dir('query_1_req', {
  test_that("Can run mid level query...", {

    expect_true(is_rosv(osv_query_1(name = 'readxl', ecosystem = 'CRAN', parse = FALSE)))
    expect_true(is_rosv(osv_query_1(name = 'readxl', ecosystem = 'CRAN', parse = TRUE)))
    expect_true(is_rosv(osv_query_1(name = 'readxl', ecosystem = 'CRAN', cache = TRUE)))
    expect_true(is_rosv(osv_query_1(name = 'readxl', ecosystem = 'CRAN', cache = FALSE)))

  })
})

