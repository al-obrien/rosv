with_mock_dir('querybatch_req', {
  test_that("Can run mid level query...", {

    expect_true(is_rosv(osv_querybatch(name = 'readxl', ecosystem = 'CRAN', parse = FALSE)))
    expect_true(is_rosv(osv_querybatch(name = 'readxl', ecosystem = 'CRAN', parse = TRUE)))
    expect_true(is_rosv(osv_querybatch(name = 'readxl', ecosystem = 'CRAN', cache = TRUE)))
    expect_true(is_rosv(osv_querybatch(name = 'readxl', ecosystem = 'CRAN', cache = FALSE)))

    expect_true(is_rosv(osv_querybatch(name = c('readxl', 'dask'), ecosystem = c('CRAN', 'PyPI'), parse = FALSE)))
    expect_true(is_rosv(osv_querybatch(name = c('readxl', 'dask'), ecosystem = c('CRAN', 'PyPI'), parse = TRUE)))
    expect_true(is_rosv(osv_querybatch(name = c('readxl', 'dask'), ecosystem = c('CRAN', 'PyPI'), cache = TRUE)))
    expect_true(is_rosv(osv_querybatch(name = c('readxl', 'dask'), ecosystem = c('CRAN', 'PyPI'), cache = FALSE)))

  })
})
