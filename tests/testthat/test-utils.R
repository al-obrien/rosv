test_that('PyPI package names can be normalized...', {
  expect_equal(normalize_pypi_pkg(c('Dask', 'TenSorFlow')), c('dask', 'tensorflow'))
})

test_that('Correct ecosystems can be checked...', {
  expect_equal(check_ecosystem(c('PyPI', 'CRAN')), c('PyPI', 'CRAN'))
  expect_error(check_ecosystem(c('pypi')))
})
