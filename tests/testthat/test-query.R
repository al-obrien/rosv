with_mock_dir('is_pkg_vul', {
  test_that("Returns named vectors with correct logic", {
    expect_equal(is_pkg_vulnerable(c('dask', 'data.table'), c('PyPI', 'CRAN')), c(dask = TRUE, data.table = FALSE))
    expect_equal(is_pkg_vulnerable(rep('readxl', 2), rep('CRAN', 2), version = c('1.4.1', '2.0.0')), c(readxl = TRUE, readxl = FALSE))
    })
})

with_mock_dir('osv_count_vul', {
  test_that("Returns named vectors with correct vuln counts", {
    expect_equal(osv_count_vulns(c( 'data.table'), c( 'CRAN')), c(data.table = 0))
    expect_equal(osv_count_vulns(c('dask', 'data.table'), c('PyPI', 'CRAN')), c(dask = 1, data.table = 0))
    expect_equal(osv_count_vulns(rep('dask',3), rep('PyPI',3), version = c('2.8.0', '9999', '2021.8.0')), c(dask = 1, dask = 0, dask = 1))
    expect_equal(osv_count_vulns(rep('readxl', 2), rep('CRAN', 2), version = c('1.4.1', '2.0.0')), c(readxl = 1, readxl = 0))
  })
})
