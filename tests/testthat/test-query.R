with_mock_dir('is_pkg_vul', {
  test_that("Returns named vectors with correct logic", {
    expect_equal(is_pkg_vulnerable(c('dask', 'data.table'), c('PyPI', 'CRAN')), c(dask = TRUE, data.table = FALSE))
    expect_equal(is_pkg_vulnerable(rep('readxl', 2), rep('CRAN', 2), version = c('1.4.1', '2.0.0')), c(readxl = TRUE, readxl = FALSE))
    })
})
